<?php
$ciphers=mcrypt_list_algorithms();
$modes	=mcrypt_list_modes();
sort($ciphers);
sort($modes);

//strip slashes from $_GET
if(get_magic_quotes_gpc())
	foreach($_GET as &$var)
		$var=stripslashes($var);
//set code values
$key=isset($_GET['hex_key'])&&$_GET['hex_key']?pack('H*',str_replace(' ','',$_GET['hex_key'])):'12345678911234567892123456789312';
$iv=isset($_GET['hex_iv'])&&$_GET['hex_iv']?pack('H*',str_replace(' ','',$_GET['hex_iv'])):'1234567891123456';
$cipher=isset($_GET['crypt'])?$_GET['crypt']:'rijndael-128';
$mode=isset($_GET['mode'])?$_GET['mode']:'cbc';
$m=isset($_GET['hex_m'])&&$_GET['hex_m']?pack('H*',str_replace(' ','',$_GET['hex_m'])):'A Plain Message';

$crypted=mcrypt_encrypt($cipher,$key,$m,$mode,$iv);

$c=isset($_GET['hex_c'])&&$_GET['hex_c']?pack('H*',str_replace(' ','',$_GET['hex_c'])):$crypted;

$plain=mcrypt_decrypt($cipher,$key,$c,$mode,$iv);


function echo_options($options,$value,$keyed=false){
	foreach($options as $key=>$o){
		$v=$keyed?$key:$o;
		echo '<option value="'.$v.($v==$value?'" selected="selected':'').'">'.$o.'</option>';
	}
}

$data=json_encode(array(
	'key'=>$key,
	'iv'=>$iv,
	'c'=>$c,
	'm'=>$m,
	'crypted'=>$crypted,
	'plain'=>$plain));
?>

<html>
<head>
<script type="text/javascript" src="rijndael.js"></script>
<script type="text/javascript" src="mcrypt.js"></script>
</head>
<body>
<?php echo mcrypt_get_key_size('rijndael-128','cbc');?>

<form name="main" action="" method="GET">
<table>
<tr><td>Key:</td><td><input name="key" size="48" onchange="data.key=this.value; setCrypt();"/></td></tr>
<tr><td>Hex Key:</td><td><textarea name="hex_key" onchange="data.key=hex2bin(this.value); setCrypt();"></textarea></td></tr>
<tr><td>Crypt:</td><td><select name="crypt" onchange="setCrypt();">
		<?php echo_options($ciphers,$cipher)?>
		</select></td></tr>
<tr><td>Mode of Operation:</td><td><select name="mode" onchange="setCrypt();">
		<?php echo_options($modes,$mode)?>
		</select></td></tr>
<tr><td>Hex IV:</td><td><input name="iv" size="48" onchange="data.iv=this.value; encrypt();"/></td></tr>
<tr><td>Hex IV:</td><td><textarea name="hex_iv" onchange="data.iv=hex2bin(this.value); encrypt();"></textarea></td></tr>

<tr><td>Plain Text:</td>
	<td><textarea name="m" onchange="data.m=this.value; encrypt();"></textarea></td></tr>
<tr><td>Hex Plain Text:</td>
	<td><textarea name="hex_m" onchange="data.m=hex2bin(this.value); encrypt();"></textarea></td></tr>
<tr><td>PHP Decrypted Text:</td>
	<td><textarea disabled="disabled"><?php echo chunk_split(bin2hex($plain),2,' ')?></textarea></td></tr>

<tr><td>Cipher Text:</td>
	<td><textarea name="c" onchange="data.c=this.value; decrypt();"></textarea></td></tr>
<tr><td>Hex Cipher Text:</td>
	<td><textarea name="hex_c" onchange="data.c=hex2bin(this.value); decrypt();"></textarea></td></tr>
<tr><td>PHP Encrypted Text:</td>
	<td><textarea disabled="disabled"><?php echo chunk_split(bin2hex($crypted),2,' ')?></textarea></td></tr>

</table>
Check With PHP's Mcrypt:<input type="submit" value="Go"/>
</form>

<script type="text/javascript">
<!--
var test='<?php ?>';
var data=<?php echo $data?>;


var setCrypt=function(){
	var cr=document.main.crypt.value;
	var mod=document.main.mode.value;
	
	data.key=pad(data.key,mcrypt.get_key_size(cr,mod));
	data.iv=pad(data.iv,mcrypt.get_iv_size(cr,mod));
	
	document.main.key.value=data.key;
	document.main.hex_key.value=bin2hex(data.key);
	
	mcrypt.Crypt(false,null,null, data.key, document.main.crypt.value, document.main.mode.value);
	
	encrypt();
}

var encrypt=function(){
	document.main.iv.value=data.iv;
	document.main.hex_iv.value=bin2hex(data.iv);
	document.main.m.value=data.m;
	document.main.hex_m.value=bin2hex(data.m);
	data.c=mcrypt.Encrypt(data.m, data.iv);
	document.main.c.value=data.c;
	document.main.hex_c.value=bin2hex(data.c);
}

var decrypt=function(){
	document.main.c.value=data.c;
	document.main.hex_c.value=bin2hex(data.c);
	data.m=mcrypt.Decrypt(data.c, data.iv);
	document.main.m.value=data.m;
	document.main.hex_m.value=bin2hex(data.m);
}	


var hexdigits='0123456789ABCDEF';
var hexLookup=Array(256);
for(var i=0;i<256;i++)
	hexLookup[i]=hexdigits.indexOf(String.fromCharCode(i));
	
var bin2hex=function(str){
	var out='';
	for(var i=0;i<str.length;i++)
		out+=hexdigits[str.charCodeAt(i)>>4]+hexdigits[str.charCodeAt(i)&15]+' ';
	return out;
}

var hex2bin=function(str){
	var out='';
	var part=-1;
	for(var i=0;i<str.length;i++){
		var t=hexLookup[str.charCodeAt(i)]
		if(t>-1){
			if(part>-1){
				out+=String.fromCharCode(part|t);
				part=-1;
			}else
				part=t<<4;
		}
	}
	return out;
}

var pad=function(x,y){
	if(x.length>=y)
		return x.substr(0,y);
	for(var i=y-x.length;i;i--)
		x+=String.fromCharCode(Math.floor(Math.random()*256));
	return x;
}

setCrypt();
-->
</script>
</body>
</html>