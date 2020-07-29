import pkg from 'node-docker-api';
import { renew, reloadContainer, download, createTempCert, deleteCert, scanConfAllFiles, sendmail, waitContainer } from './certbot.js';
import moment from 'moment';
import _ from 'lodash';

const { Docker } = pkg;

const docker = new Docker({ socketPath: '/var/run/docker.sock' });

let staging = (process.env.STAGING) ? true : false;
let email = process.env.EMAIL || 'undefined@undefined.com';

let cycle = async () => {

  download({});

  // Go through configs and see if we need to create any temp certificates
  let confs = await scanConfAllFiles({});
  for (let conf of confs) {
    if (!conf.issuer) {
      await createTempCert({ name: conf.name });
    }
  }

  // Check to see if all entries now have certs so nginx can start
  confs = await scanConfAllFiles({});
  for (let conf of confs) {      
    if (!conf.issuer) { 
      throw new Error('Some domains still no have certificates yet.');
    }
  }

  // Reload nginx incase it is crashing without proper certs
  await waitContainer({});
  await reloadContainer({});

  let actions = [];
  for (let conf of confs) {
    let renewReasons = [];

    let validTo = moment(conf.issuer.validTo);
    if (moment.duration(validTo.diff()).as('days') < 10) {
      renewReasons.push('Less than 10 days before certificate expiry.');
    }
    let domainMismatch = _.difference(conf.domains, conf.issuer.dnsNames);
    if (domainMismatch.length > 0) {
      renewReasons.push(`Domains mismatch, missing: ${ domainMismatch.join(', ') }`);
    }

    if (renewReasons.length > 0) {
      // console.log(conf.name, moment.duration(validTo.diff()).as('days'));
      await deleteCert({ name: conf.name });
      let result = await renew({
        staging,
        primaryDomain: conf.name,
        domains: conf.domains,
        email
      });
      console.log(result);

      // Record action
      actions.push({
        action: 'renewed',
        domains: conf.domains,
        renewReasons
      });
    }
  }

  if (actions.length) {
    await reloadContainer({});

    let formReasons = (reasons) => reasons.reduce((curr, next) => {
      return curr + ` - ${ next }\n`;
    }, '');

    let text = actions.reduce((curr, next) => {
      return curr +
       `Domains: ${ next.domains.join(', ') }\n` +
       `Reasons:\n` +
       `${ formReasons(next.renewReasons) }\n\n`;
    }, '');

    await sendmail({ 
      from: 'mailer@psidox.com',
      to: 'josh@psidox.com',
      subject: 'Certbot renewed certificates.',
      text,
    });
  }

}


(async () => {

  cycle();
  setInterval(cycle, 60 * 60 * 24 * 1000);
                                       
})();
