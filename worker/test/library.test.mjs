import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "../index.js";

function testEnv() {
  const values = new Map();
  const expiration = [];
  return {
    values, expiration, AUTH_SECRET: "library-test-key",
    USER_STORE: {
      async get(key) { return values.get(key) || null; },
      async put(key, value, options) { values.set(key, value); expiration.push({key,options}); },
      async delete(key) { values.delete(key); },
      async list({prefix, cursor, limit=1000}) {
        const all = [...values.keys()].filter(key => key.startsWith(prefix)).sort();
        const start = Number(cursor || 0), part = all.slice(start, start + limit);
        return { keys: part.map(name=>({name})), cursor: String(start+limit),
          list_complete: start + limit >= all.length };
      }
    }
  };
}
function api(env) {
  let token = "";
  const request = async (route, method="GET", body) => {
    const headers = {Origin:"https://tbushueff-tech.github.io"};
    if (token) headers.Authorization = "Bearer " + token;
    const response = await worker.fetch(new Request("https://test.example" + route, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body)
    }), env);
    return {status:response.status, data: await response.json()};
  };
  return {
    async login(username) {
      const r = await request("/auth/register", "POST", {username,password:"testing-password",
        crypto:{v:1,salt:"s",iv:"i",wrappedKey:"k"}});
      assert.equal(r.status, 201);
      token = r.data.token;
    },
    request
  };
}
const sample = (id, revision=0) => ({
  id, v:2, iv:"AAAAAAAAAAAAAAAA",ciphertext:"A".repeat(180),revision
});

test("permanent library saves encrypted content without expiry and does not modify clipboard", async () => {
  const env=testEnv(), a=api(env); await a.login("alpha");
  const created=await a.request("/library", "POST", sample("first"));
  assert.equal(created.status,200);
  assert.equal(created.data.revision,1);
  assert.ok(env.values.has("library:alpha:first"));
  const put=env.expiration.find(x=>x.key==="library:alpha:first");
  assert.equal(put.options,undefined,"library KV must have no expiration");
  const clipboard=await a.request("/","GET");
  assert.deepEqual(clipboard.data.items,[]);
  const list=await a.request("/library");
  assert.deepEqual(list.data.items,[{id:"first"}]);
  const meta=await a.request("/library/first?meta=1");
  assert.equal(meta.data.revision,1);
  let next=0, body="";
  while(next<meta.data.total) {
    const c=await a.request("/library/first?chunk="+next);
    assert.equal(c.status,200);
    body+=c.data.chunk;next+=c.data.chunk.length;
  }
  assert.deepEqual(JSON.parse(body),{...sample("first"),revision:1});
  const changed=await a.request("/library","POST",sample("first",1));
  assert.equal(changed.data.revision,2);
  assert.equal((await a.request("/library","POST",sample("first",1))).status,409);
  assert.equal((await a.request("/library/first?revision=1","DELETE")).status,409);
  assert.equal((await a.request("/library/first?revision=2","DELETE")).status,200);
  assert.equal((await a.request("/library")).data.items.length,0);
});

test("library is isolated per user; unauthenticated requests fail", async () => {
  const env=testEnv(), alice=api(env), bob=api(env);
  await alice.login("alice"); await bob.login("bob");
  assert.equal((await alice.request("/library", "POST",sample("secret"))).status,200);
  assert.equal((await bob.request("/library")).data.items.length,0);
  assert.equal((await bob.request("/library/secret?meta=1")).status,404);
  const direct=await worker.fetch(new Request("https://test.example/library"),env);
  assert.equal(direct.status,401);
});

test("encrypted library list is paginated in small responses",async()=>{
  const env=testEnv(),a=api(env);await a.login("manyitems");
  for(let i=0;i<45;i++) env.values.set("library:manyitems:"+String(i).padStart(3,"0"),JSON.stringify(sample(String(i))));
  const first=await a.request("/library");
  assert.equal(first.data.items.length,40);
  assert.ok(first.data.nextCursor);
  const second=await a.request("/library?cursor="+encodeURIComponent(first.data.nextCursor));
  assert.equal(second.data.items.length,5);
});
