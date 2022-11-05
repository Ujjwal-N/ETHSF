import Koa from 'koa';
import Router from '@koa/router';

import { isReady, PrivateKey, Field, Signature, Poseidon } from 'snarkyjs';

const PORT = process.env.PORT || 3000;

const app = new Koa();
const router = new Router();

const numValidators = 4;

async function signData(ach) {
  await isReady;
  var outputString = 'ACH: ' + ach + '\n';

  const privateKey = PrivateKey.fromBase58(
    process.env.PRIVATE_KEY ??
      'EKF65JKw9Q1XWLDZyZNGysBbYG21QbJf3a4xnEoZPZ28LKYGMw53'
  );

  const publicKey = privateKey.toPublicKey();

  const subKeys = [];

  for (var i = 1; i < numValidators + 1; i++) {
    outputString += 'Validator ' + i + ': ';

    const privKeyFields = PrivateKey.random().toFields();
    privKeyFields.push(Field(ach));
    const curKey = Poseidon.hash(privKeyFields);

    subKeys.push(curKey);
    outputString += curKey + '\n';

    // const curSig = Signature.create(privateKey, [Field(i), curKey]);
    // subSignatures.push(curSig);
    // outputString += curSig + "\n";
  }
  outputString += 'Transferring subkeys to validators...\n';

  const topLevelHash = Poseidon.hash(subKeys);
  outputString += 'Top Level Hash: ' + topLevelHash;

  const signature = Signature.create(privateKey, [Field(ach), topLevelHash]);

  return {
    data: { ach: ach, topLevelHash: topLevelHash },
    signature: signature,
    publicKey: publicKey,
    display: outputString,
  };
}

router.get('/ach/:ach', async (ctx) => {
  let signedData = await signData(ctx.params.ach);
  ctx.body =
    'Signature(r,s):' +
    '(' +
    signedData.signature.r.toString() +
    ', ' +
    signedData.signature.s.toJSON().toString() +
    ')' +
    '\n' +
    signedData.display;
});

router.get('/ach-api/:ach', async (ctx) => {
  ctx.body = await signData(ctx.params.ach);
});


router.get('/', async (ctx) => {
  ctx.body = "Welcome!"
});


app.use(router.routes()).use(router.allowedMethods());

app.listen(PORT);
