const { newEnforcer } = require('casbin');
const path = require('path');

// Initialize Casbin with the policy file
async function initEnforce(s, o, a) {
  const enforcer = await newEnforcer(path.join(__dirname, 'model.conf'), path.join(__dirname, 'policy.csv'));
  r = await enforcer.enforce(s, o, a);
  return { res: r, sub: s, obj: o, act: a };
}

async function isAllowed(allowed) {
  if (allowed.res) {
    console.log(`${allowed.sub} is allowed to ${allowed.act} ${allowed.obj}`);
  } else {
    console.log(`${allowed.sub} is not allowed to ${allowed.act} ${allowed.obj}`);
  }
}

async function main() {
  initEnforce('alice', 'data1', 'read').then(isAllowed);
  initEnforce('alice', 'data1', 'write').then(isAllowed);
  initEnforce('rauljcsantos@gmail.com', '/list/whatever', 'read').then(isAllowed);
}
/*
main().then(() => {
  console.log('Finished');
}).catch((err) => {
  console.log(err);
});*/

module.exports = { initEnforce, isAllowed };