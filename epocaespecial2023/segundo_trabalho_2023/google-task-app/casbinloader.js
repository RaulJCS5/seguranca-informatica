const { newEnforcer } = require('casbin');
const path = require('path');

// Initialize Casbin with the policy file
async function init() {
  const enforcer = await newEnforcer(path.join(__dirname, 'model.conf'), path.join(__dirname, 'policy.csv'));
  return enforcer;
}

async function isAllowed(enforcer, sub, obj, act) {
  const allowed = await enforcer.enforce(sub, obj, act);
  if (allowed) {
    console.log('Allowed');
    return { allowed, sub, obj, act };
  } else {
    console.log('Denied');
    return { allowed, sub, obj, act };
  }
}

async function main() {
  const enforcer = await init();
  // Modify the policy.
  //await enforcer.addPolicy('alice', 'data1', 'read');

  //await enforcer.removePolicy('alice', 'data1', 'read');

  // Save the policy back to file.
  // await enforcer.savePolicy();
  // Check the permission.
  const result = await isAllowed(enforcer, 'alice', 'data1', 'read');
  console.log(result);
}

main().then(() => {
  console.log('Finished');
}).catch((err) => {
  console.log(err);
});

module.exports = { init, isAllowed };