import { expand_message, hash_to_field, to_hex_string } from "./utils";
import { ContractTransaction, randomBytes, toUtf8Bytes,utils } from "ethers";
import { hexToUint8Array } from "thirdweb/utils";

var JSONbig = require('json-bigint');

const domain = "BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_";
let obj={};
//for (let msg_len = 10; msg_len < 256; ++msg_len)
//{
	//const message = randomBytes(msg_len);
        const message =  hexToUint8Array(0x39a98b55149298738dac);
	const rhs0 = expand_message(toUtf8Bytes(domain), message, 96);
        console.log(message, rhs0);

	//let view = new DataView(message.buffer, 0);
	//let msg = view.getBigUint64(0, true);
        const msg = `0x${Array.from(message)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("")}`;
        console.log(msg);

        //let viewTwo = new DataView(rhs0.buffer, 0);
        //let output = viewTwo.getBigUint64(0, true);
        console.log(output);
        const rhs = `0x${Array.from(rhs0)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("")}`;
        obj[msg_len] = [msg, rhs]; 
//}
console.log(JSONbig.stringify(obj, null, 2));
