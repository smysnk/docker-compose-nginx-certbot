import https from 'https';
import fs from 'fs';
import axios from 'axios';
import ncp from 'nginx-config-parser';
import _ from 'lodash';
import glob from 'glob';
import nodemailer from 'nodemailer';

import x509 from '@fidm/x509';
const { Certificate } = x509;

import nda from 'node-docker-api';
const { Docker } = nda;

const docker = new Docker({ socketPath: '/var/run/docker.sock' });

const promisifyStream = stream => new Promise((resolve, reject) => {
  let content = "";
  stream.on('data', data => { 
    content += data.toString();
  });
  stream.on('end', () => { resolve(content) });
  stream.on('error', reject);
});

async function scanConfAllFiles({ path='/etc/nginx/conf.d/*.conf' }) {
  let files = glob.sync(path);
  let confs = [];

  for (let file of files) {
    let scan = await scanConf({ path: file });
    confs = confs.concat(scan);
  }

  return confs;
}

async function scanConf({ path }) {

  var config = ncp.queryFromString(fs.readFileSync(path, 'utf-8'));
  let domains = config[0].server.reduce((acc, server) => {
    if (server.ssl_certificate) {
      
      let certName = server.ssl_certificate[0][0].match(/live\/(.*)\//);
      if (certName == null) {
        return acc;
      }
      
      let entry = _.find(acc, { 'name': certName[1] });
      if (!entry) {
        entry = {
          name: certName[1],
          domains: [],
        };
        acc.push(entry);
      }

      entry.domains = server['server_name'][0].concat(entry.domains);
    }
    return acc;
  }, []);

  domains.forEach(domain => {
    domain.issuer = null;
    try {
      domain.issuer = Certificate.fromPEM(fs.readFileSync(`/etc/letsencrypt/live/${ domain.name }/fullchain.pem`));
    } catch(e) {
    }
  });

  return domains;

}

async function createTempCert({ name }) {

  const pathContainer = '/etc/letsencrypt/live';  
  let path = (process.env.PATH_OVERRIDE) ? pathOverride : pathContainer;

  console.log('Create certificate.');
  if (!fs.existsSync(`${ path }/${ name }`)) {
    console.log(`Creating directory [${ path }/${ name }].`);
    fs.mkdirSync(`${ path }/${ name }`, { recursive: true });
  } else {
    console.log(`Path [${ path }/${ name }] already exists.`)
  }

  path = pathContainer;

  let list = await docker.container.list({ all: true });
  let item = list.find((item) => {
    // console.log(item);
    return item.data.Image == 'certbot/certbot';
  });
  
  return item.exec.create({
    AttachStdout: true,
    AttachStderr: true,
    Cmd: [ '/bin/sh', '-c', `openssl req -x509 -nodes -newkey rsa:1024 -days 1 \
    -keyout '${ path }/${ name }/privkey.pem' \
    -out '${ path }/${ name }/fullchain.pem' \
    -subj '/CN=localhost'` ]
  }).then(exec => {
    return exec.start({ Detach: false })
  }).then(stream => promisifyStream(stream));

}


async function renew({ staging=false, primaryDomain, domains, email }) {

  let filterDomains = _.without(domains, primaryDomain);

  console.log('Renewing certificate.');
  let list = await docker.container.list({ all: true });
  let item = list.find((item) => {
    return item.data.Image == 'certbot/certbot';
  });

  let stagingFlag = (staging) ? '--staging' : '';
  filterDomains = filterDomains.reduce((acc, item) => {
    return acc + `-d ${ item } `
  }, '');

  console.log(`certbot certonly --break-my-certs --webroot -w /var/www/certbot -d ${ primaryDomain } ${ filterDomains } --email ${ email } --rsa-key-size 4096 --agree-tos --force-renewal ${ stagingFlag }`);
  
  return item.exec.create({
    AttachStdout: true,
    AttachStderr: true,
    Cmd: [ '/bin/sh', '-c', `certbot certonly --break-my-certs --webroot -w /var/www/certbot -d ${ primaryDomain } ${ filterDomains } --email ${ email } --rsa-key-size 4096 --agree-tos --force-renewal ${ stagingFlag }` ]
  }).then(exec => {
    return exec.start({ Detach: false })
  }).then(stream => promisifyStream(stream));

}

async function reloadContainer() {

  console.log('Reloading Nginx.');
  let list = await docker.container.list({ all: true });
  let item = list.find((item) => {
    return item.data.Image == 'nginx:1.19-alpine';
  });

  return item.exec.create({
    AttachStdout: true,
    AttachStderr: true,
    Cmd: [ '/bin/sh', '-c', 'nginx -s reload' ]
  }).then(exec => {
    return exec.start({ Detach: false })
  })
  .then(stream => promisifyStream(stream))
  .catch(error => console.log(error));

}

async function waitContainer() {

  console.log('Wait for Nginx running.');
  let sleep = () => new Promise(r => setTimeout(r, 1000));
  while (true) {
    console.log('...');
    let list = await docker.container.list({ all: true });
    let container = list.find((item) => {
      return item.data.Image == 'nginx:1.19-alpine';
    });
    if (container.data.State === 'running') {
      // Wait for state = running
      break;
    }
    await sleep();
  }

}

async function deleteCert({ name, path='/etc/letsencrypt' }) {

  if (fs.existsSync(`${ path }/live/${ name }`)) {
    fs.rmdirSync(`${ path }/live/${ name }`, { recursive: true });
  }
  if (fs.existsSync(`${ path }/archive/${ name }`)) {
    fs.rmdirSync(`${ path }/archive/${ name }`, { recursive: true });
  }
  if (fs.existsSync(`${ path }/renewal/${ name }.conf`)) {
    fs.unlinkSync(`${ path }/renewal/${ name }.conf`);
  }
}

async function download({ path='/etc/letsencrypt' }) {
  let files = [
    {
      url: 'https://raw.githubusercontent.com/certbot/certbot/master/certbot-nginx/certbot_nginx/_internal/tls_configs/options-ssl-nginx.conf',
      destination: `${ path }/options-ssl-nginx.conf`
    },
    {
      url: 'https://raw.githubusercontent.com/certbot/certbot/master/certbot/certbot/ssl-dhparams.pem',
      destination: `${ path }/ssl-dhparams.pem`,
    },
  ];

  if (!fs.existsSync(path)) {
    console.log(`Creating directory [${ path }].`);
    fs.mkdirSync(path);
  } else {
    console.log(`Path [${ path }] already exists.`)
  }

  for (let file of files) {
    await axios({
      method: 'get',
      url: file.url,
      responseType: 'stream'
    })
      .then(function (response) {
        response.data.pipe(fs.createWriteStream(file.destination))
      });
  }   
}

async function sendmail({ from='mailer@example.com', to='recipient@example.com', subject='', text='' }) {

  let transporter = nodemailer.createTransport({
    host: "email-smtp.us-east-1.amazonaws.com",
    port: 465,
    secure: true, // upgrade later with STARTTLS
    auth: {
      user: process.env.SMTP_USERNAME,
      pass: process.env.SMTP_PASSWORD,
    }
  });

  // send some mail
  transporter.sendMail({
    from,
    to,
    subject,
    text,
  }, (err, info) => {
    console.log(info, err);
  });

}

export {
  renew,
  reloadContainer,
  deleteCert,
  download,
  createTempCert,
  scanConfAllFiles,
  sendmail,
  waitContainer
};