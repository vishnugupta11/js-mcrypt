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
$key=isset($_GET['key'])?$_GET['key']:'12345678911234567892123456789312';
$iv=isset($_GET['iv'])?$_GET['iv']:'1234567891123456';
$cipher=isset($_GET['crypt'])?$_GET['crypt']:'rijndael-128';
$mode=isset($_GET['mode'])?$_GET['mode']:'cbc';
$m=(isset($_GET['m'])&&$_GET['m'])?$_GET['m']:'A Plain Message';


$crypted=mcrypt_encrypt($cipher,$key,$m,$mode,$iv);

$c=(isset($_GET['c'])&&$_GET['c'])?$_GET['c']:$crypted;

$plain=mcrypt_decrypt($cipher,$key,$c,$mode,$iv);


function echo_options($options,$value,$keyed=false){
	foreach($options as $key=>$o){
		$v=$keyed?$key:$o;
		echo '<option value="'.$v.($v==$value?'" selected="selected':'').'">'.$o.'</option>';
	}
}
?>

<html>
<head>
<script type="text/javascript" src="rijndael.js"></script>
<script type="text/javascript" src="mcrypt.js"></script>
</head>
<body>


<form name="main" action="" method="GET">
<table>
<tr><td>Hex Key:</td><td><input name="key" value="<?php echo $key?>" onchange="setCrypt();"/></td></tr>
<tr><td>Crypt:</td><td><select name="crypt" onchange="setCrypt();">
		<?php echo_options($ciphers,$cipher)?>
		</select></td></tr>
<tr><td>Mode of Operation:</td><td><select name="mode" onchange="setCrypt();">
		<?php echo_options($modes,$mode)?>
		</select></td></tr>
<tr><td>Hex IV:</td><td><input name="iv" value="<?php echo $iv?>" onchange="encrypt();"/></td></tr>
<tr><td>Plain Text:</td><td><textarea name="m" onchange="encrypt();"><?php echo $m?></textarea></td></tr>
<tr><td>PHP Decrypted Text:</td><td><textarea disabled="disabled"><?php echo $plain?></textarea></td></tr>
<tr><td>Cipher Text:</td><td><textarea name="c"
onchange="document.main.m.value=mcrypt.Decrypt(document.main.c.value, document.main.iv.value);"><?php echo $c?></textarea></td></tr>
<tr><td>PHP Encrypted Text:</td><td><textarea disabled="disabled"><?php echo $crypted?></textarea></td></tr>
</table>
Check With PHP's Mcrypt:<input type="submit" value="Go"/>
</form>

<script type="text/javascript">
<!--
var setCrypt=function(){
	mcrypt.Crypt(false,null,null, document.main.key.value, document.main.crypt.value, document.main.mode.value);
	encrypt();
}

var encrypt=function(){
	document.main.c.value=mcrypt.Encrypt(document.main.m.value, document.main.iv.value);
}

setCrypt();
-->
</script>
</body>
</html>