/*
 *  jsmcrypt version 0.1  -  Copyright 2012 F. Doering
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307 USA
 */
 
 var mcrypt=mcrypt?mcrypt:new function(){
  /**********
 * Private *
 **********/
 
 /************************
 * START OF CIPHER DEFFS *
 ************************/
 
 /* Cipher Data
 * This is an object, keyed with the cipher name whose value is an
 * array containing the number of octets (bytes) in the block size,
 * and the number of octets in the key.
 */
 var ciphers={			//	block size,	key size
  "MCRYPT_RIJNDAEL_x"	:[	16,			0],
  "MCRYPT_RIJNDAEL_128"	:[	16,			32],
  "MCRYPT_RIJNDAEL_192"	:[	16,			48],
  "MCRYPT_RIJNDAEL_256"	:[	16,			64],
 }
 
 /* Storage
 * for saving values used to speed up repeated calls
 */
 var SpeedStorage={
 "MCRYPT_RIJNDAEL_X":{
		"ExpandedKeys":{}
		},
 }
 
 /* blockCipherCalls
 * This object is keyed by the cipher names and the vaules are
 * functions that calls external block ciphers to encypt or
 * decrypt a single block. These functions must have the arguments:
 * function(cipher_name,block,key,encrypt)
 * where: chipher_name is the text of the cipher name,
 * block is an array of inegers representing octets
 * key is a string
 * and encrypt indicates whether it should encrypt or decrypt
 * the block.
 * the function should modify the block as its output
 */
 var blockCipherCalls={};
 blockCipherCalls.MCRYPT_RIJNDAEL_x=function(cipher,block,key,encrypt){
	if(!SpeedStorage.MCRYPT_RIJNDAEL_X.ExpandedKeys[key]){
		var keyA=new Array(key.length);
		for(var i=key.length-1 ; i>=0 ; i--)
			keyA[i]=key.charCodeAt(i);
		Rijndael.ExpandKey(keyA);
		SpeedStorage.MCRYPT_RIJNDAEL_X.ExpandedKeys[key]=keyA;
	}
	if(encrypt)
		Rijndael.Encrypt(block,SpeedStorage.MCRYPT_RIJNDAEL_X.ExpandedKeys[key]);
	else
		Rijndael.Decrypt(block,SpeedStorage.MCRYPT_RIJNDAEL_X.ExpandedKeys[key]);
	return block;
 };
 blockCipherCalls.MCRYPT_RIJNDAEL_128=blockCipherCalls.MCRYPT_RIJNDAEL_x;
 blockCipherCalls.MCRYPT_RIJNDAEL_192=blockCipherCalls.MCRYPT_RIJNDAEL_x;
 blockCipherCalls.MCRYPT_RIJNDAEL_256=blockCipherCalls.MCRYPT_RIJNDAEL_x;

 
 /**********************
 * END OF CIPHER DEFFS *
 **********************/
 
 /*********
 * Public *
 *********/ 
 var pub={};
 
 /* Encrypt
 * This function encypts a plaintext message with an IV, key,  ciphertype, and mode
 * The message, key, and IV should be extended ascii strings
 * the ciphertype should be a string that is a supported cipher (see above)
 * the mode should be a string that is a supported mode of operation
 * the key, cipher type, and mode will default to the last used
 * these can be set without encypting by "encrypting" a null message
 */
 pub.Encrypt=function(message,IV,key, cipher, mode){
	return pub.Crypt(true,message,IV,key, cipher, mode);
};
/* Decrypt
 * See Encrypt for usage
 */ 
 
 pub.Decrypt=function(ctext,IV,key, cipher, mode){
	return pub.Crypt(false,ctext,IV,key, cipher, mode);
 };
/* Crypt
 * This function can encrypt or decrypt text
 */
 
pub.Crypt=function(encrypt,text,IV,key, cipher, mode){
	if(key) cKey=key; else key=cKey;
	if(cipher) cCipher=cipher; else cipher=cCipher;
	if(mode) cMode=mode; else mode=cMode;
	if(!text)
		return true;
	var blockS=ciphers[cipher][0];
	var chunkS=blockS;
	var iv=new Array(blockS);
	switch(mode){
		case 'cbc':
		case 'ncfb':
		case 'nofb':
			if(!IV)
				throw "mcrypt.Crypt: IV Required for mode "+mode;
			if(IV.length!=blockS)
				throw "mcrypt.Crypt: IV must be "+blockS+" characters long for "+cipher;
			for(var i = blockS-1; i>=0; i--)
				iv[i] = IV.charCodeAt(i);
			break;
		case 'ecb':
			break;
		default:
			throw "mcrypt.Crypt: Unsupported mode of opperation"+cMode;
	}
	var chunks=Math.ceil(text.length/chunkS);
	var orig=text.length;
	text+=Array(chunks*chunkS-orig+1).join(String.fromCharCode(0));//zero pad the end
	var out='';
	switch(mode){
		case 'ecb':
			for(var i = 0; i < chunks; i++){
				for(var j = 0; j < chunkS; j++)
					iv[j]=text.charCodeAt((i*chunkS)+j);
				blockCipherCalls[cipher](cipher,iv, cKey,encrypt);
				for(var j = 0; j < chunkS; j++)
					out+=String.fromCharCode(iv[j]);
			}
			return out;
		case 'cbc':
			if(encrypt){
				for(var i = 0; i < chunks; i++){
					for(var j = 0; j < chunkS; j++)
						iv[j]=text.charCodeAt((i*chunkS)+j)^iv[j];
					blockCipherCalls[cipher](cipher,iv, cKey,true);
					for(var j = 0; j < chunkS; j++)
						out+=String.fromCharCode(iv[j]);
				}
			}
			else{
				for(var i = 0; i < chunks; i++){
					var temp=iv;
						iv=new Array(chunkS);
					for(var j = 0; j < chunkS; j++)
						iv[j]=text.charCodeAt((i*chunkS)+j);
					var decr=iv.slice(0);
					blockCipherCalls[cipher](cipher,decr, cKey,false);
					for(var j = 0; j < chunkS; j++)
						out+=String.fromCharCode(temp[j]^decr[j]);
				}
			}
			return out;
		case 'ncfb':
			for(var i = 0; i < chunks; i++){
				blockCipherCalls[cipher](cipher,iv, cKey,true);
				for(var j = 0; j < chunkS; j++){
					var temp=text.charCodeAt((i*chunkS)+j);
					iv[j]=temp^iv[j];
					out+=String.fromCharCode(iv[j]);
					if(!encrypt)
						iv[j]=temp;
				}
			}
			return out.substr(0,orig);
		case 'nofb':
			for(var i = 0; i < chunks; i++){
				blockCipherCalls[cipher](cipher,iv, cKey,true);
				for(var j = 0; j < chunkS; j++)
					out+=String.fromCharCode(text.charCodeAt((i*chunkS)+j)^iv[j]);
			}
			return out.substr(0,orig);
	}
	return false;
};
 
 /**********
 * Private *
 **********/
  
 var cMode='cbc';
 var cCipher='MCRYPT_RIJNDAEL_128';
 var cKey='12345678911234567892123456789312';


return pub; 
};