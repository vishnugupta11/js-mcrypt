<html>
<head>
<script type="text/javascript" src="rijndael.js"></script>
<script type="text/javascript" src="mcrypt.js"></script>
</head>
<body>
<form name="main" action="" method="GET">
Hex Key:<input name="key" value=""/>
</form>
<script type="text/javascript">
<!--
<?php 
$key='12345678911234567892123456789312';
$iv='1234567891123456';
$mode='nofb';
$cipher='MCRYPT_RIJNDAEL_128';
?>
//set key, crypt and mode;
mcrypt.Crypt(false,null,null,'<?php echo $key?>','<?php echo $cipher?>','<?php echo $mode?>');
var text = '';
for(var i = 0; i < 60; i++)
  text += String.fromCharCode((0x08 * i)%250);

  
var blocka=new Array(text.length);
for(var i = 0; i < text.length; i++)
	blocka[i]=text.charCodeAt(i);
document.write(blocka+'<br/>\n');

text=mcrypt.Encrypt(text, '<?php echo $iv?>');

var blockb=new Array(text.length);
for(var i = 0; i < text.length; i++)
	blockb[i]=text.charCodeAt(i);

text=mcrypt.Decrypt(text, '<?php echo $iv?>');

var blocka=new Array(text.length);
for(var i = 0; i < text.length; i++)
	blocka[i]=text.charCodeAt(i);
document.write(blocka+'<br/>\n');

document.write(blockb+'<br/>\n');
-->
</script>
<?php
$block='';
for($i=0; $i<60;$i++)
	$block.=chr((0x08*$i)%250);
$crypted=mcrypt_encrypt(constant($cipher),$key,$block,$mode,$iv);
for($i=0;$i<strlen($crypted);$i++)
	echo ord($crypted[$i]).',';
echo "<br/>\n";
$crypted=mcrypt_decrypt(constant($cipher),$key,$crypted,$mode,$iv);
for($i=0;$i<strlen($crypted);$i++)
	echo ord($crypted[$i]).',';
echo "<br/>\n"
?>
</body>
</html>