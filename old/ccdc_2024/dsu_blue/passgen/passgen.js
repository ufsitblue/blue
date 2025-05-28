function hex2bigint(hex) {
  ret = 0n;
  for(let i = 0; i < hex.length; i += 2) ret = (ret << 8n) | BigInt(parseInt(hex.slice(i,i+2),16));
  return ret;
}

// async function sha256(ascii) {
//   const textEncoder = new TextEncoder();
//   const data = await crypto.subtle.digest("SHA-256", textEncoder.encode(ascii));
//   return Array.from(new Uint8Array(data)).map(x => x.toString(16).padStart(2,'0')).join('');
// }

function trun64(val) {
  return val & 0xFFFFFFFFFFFFFFFFn;
}

function rol64(x, k) {
  const X = BigInt(x);
  const K = BigInt(k);
  return trun64(X << K) | trun64(X >> (64n - K));
}

function bigIntToU64Array(val) {
  const ret = [];
  while(val != 0n) {
    ret.push(val & 0xFFFFFFFFFFFFFFFFn);
    val >>= 64n;
  }
  return ret;
}

function u64ArrayToBigInt(arr) {
  let ret = 0n;
  for(let i = arr.length - 1; i >= 0; i--) {
    ret <<= 64n;
    ret += trun64(BigInt(arr[i]));
  }
  return ret;
}

function randBigInt() {
  let ret = 0n;
  for(let i = 0; i < 16; i++) {
    ret <<= 16n;
    ret += BigInt(Math.floor(Math.random() * 65536));
  }
  return ret;
}

const progressBar = document.getElementById("progressBar");
const progressCounter = document.getElementById("progressCounter");
function setProgressBar(current, total) {
  const pct = current / total * 200;
  progressCounter.textContent = `${current} / ${total}`;
  progressBar.style.width = `${pct}px`;
}

// Constants for word generation
consonants = ["b","k","d","f","g","h","j","l","m","n","p","r","s","t","v","w","y","z","bl","cl","fl","gl","pl","br","cr","dr","fr","gr","pr","tr","sk","sl","sp","st","sw","spr","str","ch","sh","th","th","wh","ng","nk"];
vowels = ["a","e","i","o","u","oo","oi","ow","ey","oo","aw"];
symbols = ["!", "@", "#", "$", "%", "^", "&", "*", "?", "_", "-", "+", "="];

// PRNG class
class XorshiftGenerator {
  constructor(seed, size=256) {
    this.state = BigInt(seed);
    this.size  = BigInt(size);
  }

  // Old Xorshift (not secure)
  // advance(rounds=1) {
  //   for(let i = 0; i < rounds; i++) {
  //     this.state ^= this.state << 13n;
  //     this.state ^= this.state >> 17n;
  //     this.state ^= this.state << 5n;
  //     this.state &= 2n ** this.size - 1n;
  //   }
  //   return this.state;
  // }

  // Xoshiro256** (Hopefully more secure)
  advance(rounds=1) {
    let s = bigIntToU64Array(this.state);
    let result;
    for(let i = 0; i < rounds; i++) {
      result = trun64(rol64(s[1] * 5n, 7n) * 9n);
      const t = s[1] << 17n;

      s[2] ^= s[0];
      s[3] ^= s[1];
      s[1] ^= s[2];
      s[0] ^= s[3];

      s[2] ^= t;
      s[3] = rol64(s[3], 45n);
    }

    this.state = u64ArrayToBigInt(s);
    return result;
  }

	advance256(rounds=1) {
    const value = this.advance(rounds);
		return (value >> ((value >> 58n) % 56n)) & 255n;//ret[ret[0] % (len(ret) - 1) + 1];
	}

  choice(iter) {
    return iter[this.advance256() % BigInt(iter.length)];
  }

  join(words, delimiters) {
    let ret = [];
    words.forEach(i => {
      ret.push(i);
      ret.push(this.choice(delimiters));
    });
    return ret.slice(0,ret.length - 1).join('');
  }
  
  genWord(length=5) {
    let ret = [];
    for(let i = 0; i < length; i++)
      ret.push(this.choice(i % 2 ? vowels : consonants));
    return ret.join('');
  }

  genPassword(words=2, numbers=1) {
    let ret = [];
    for(let i = 0; i < words; i++)
      ret.push(this.genWord());
    for(let i = 0; i < numbers; i++) {
			const numArray = [];
			for(let j = 0; j < 4; j++) numArray.push(this.advance256() % 10n);
			ret.push(numArray.join(''));
		}
    return this.join(ret, symbols);
  }
}

(async () => {
  const seedInput          = document.getElementById("seedInput");
  const roundsInput        = document.getElementById("roundsInput");
  const copyPasswordButton = document.getElementById("copyPasswordButton");
  const showPasswordButton = document.getElementById("showPasswordButton");
  const userNamesInput     = document.getElementById("userNamesInput");
  const copyUserListPasswordButton   = document.getElementById("copyUserListPasswordButton");
  const showUserListPasswordButton   = document.getElementById("showUserListPasswordButton");
  const userListItemDelimiterInput   = document.getElementById("userListItemDelimiterInput");
  const userListRecordDelimiterInput = document.getElementById("userListRecordDelimiterInput");
  const downloadUserListPasswordButton = document.getElementById("downloadUserListPasswordButton");
  const downloadLink                   = document.getElementById("downloadLink");
  const userListFileName               = document.getElementById("userListFileName");
  const clipboardClearButton           = document.getElementById("clipboardClearButton");

  async function passwordFromForm() {
    if(seedInput.value.length == 0) {
      alert("No seed present");
      throw new Error("No seed present");
    }

    const prng = new XorshiftGenerator(hex2bigint(await sha256(seedInput.value)));
    prng.advance(parseInt(roundsInput.value));
  
    return prng.genPassword();
  }

  copyPasswordButton.addEventListener("click", async e => {
    navigator.clipboard.writeText(await passwordFromForm());
  });

  showPasswordButton.addEventListener("click", async e => {
    alert(await passwordFromForm());
  });

  async function verifyDelimiterHandler(event) {
    if(
      symbols.includes(event.target.value) ||
      consonants.includes(event.target.value) ||
      vowels.includes(event.target.value)
    ) {
      alert("Invalid Delimiter: " + event.target.value);
      event.target.value = '';
      return false;
    }
  }

  userListItemDelimiterInput.addEventListener("change", verifyDelimiterHandler);
  userListRecordDelimiterInput.addEventListener("change", verifyDelimiterHandler);

  function passwordsFromUserList() {
    if(seedInput.value.length == 0) {
      alert("No seed present");
      throw new Error("No seed present");
    }
    const names = userNamesInput.value.split("\n").filter(n => n.length > 0);
    const ret = [];
    const promise = new Promise((resolve, reject) => {
      let i = 0;
      const genPassword = function() {
        const prng = new XorshiftGenerator(hex2bigint(sha256(seedInput.value + names[i])));
        prng.advance(parseInt(roundsInput.value));
        ret.push([names[i], prng.genPassword()]);
        setProgressBar(parseInt(i) + 1, names.length);
        i++;
        if(i < names.length) setTimeout(genPassword, 10);
        else setTimeout(() => resolve(ret), 10);
      }
      setTimeout(genPassword, 10);
    })
    return promise;
  }

  async function table2delim(table, itemDelimiter, recordDelimiter) {
    table.forEach(record => {
      let abort = true;
      if(record[0].includes(itemDelimiter))
        abort &= confirm(`Record '${record[0]}' contains '${itemDelimiter}'. Continue?`);
      if(record[0].includes(recordDelimiter))
        abort &= confirm(`Record '${record[0]}' contains '${recordDelimiter}'. Continue?`);

      if(!abort) throw new Error('Record contained delimiter');
    });
    return table.map(line => line.join(itemDelimiter)).join(recordDelimiter);
  }

  copyUserListPasswordButton.addEventListener("click", async e => {
    navigator.clipboard.writeText(await table2delim(
      await passwordsFromUserList(),
      decodeURIComponent(userListItemDelimiterInput.value || ','),
      decodeURIComponent(userListRecordDelimiterInput.value || '%0A')
    ));
  });

  showUserListPasswordButton.addEventListener("click", async e => {
    alert(await table2delim(
      await passwordsFromUserList(),
      decodeURIComponent(userListItemDelimiterInput.value || ','),
      decodeURIComponent(userListRecordDelimiterInput.value || '%0A')
    ));
  });

  downloadUserListPasswordButton.addEventListener("click", async e => {
    downloadLink.download = userListFileName.value;
    downloadLink.href = "data:text/plain," + encodeURIComponent(await table2delim(
      await passwordsFromUserList(),
      ',',
      '\n'
    ));
    downloadLink.click();
  });

  clipboardClearButton.addEventListener("click", async e => {
    const prng = new XorshiftGenerator(randBigInt());
    const dummies = Math.floor(Math.random() * 128);
    for(let i = 0; i < dummies; i++) {
      setTimeout(() => navigator.clipboard.writeText(prng.genPassword()), Math.random() * 1000);
    }
    setTimeout(() => alert("Clipboard Cleared"), 1000);
  });
})();