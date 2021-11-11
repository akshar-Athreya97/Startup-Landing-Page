const fs = require("fs");
let d = new Date();
const testJson = require("./result.json");
var release=process.argv.slice(3)
let htmlBoilerplateStart = `<html lang="en">
<head>
<style>
* {
  font-family: "Courier New";
  background-color: LavenderBlush;
}
h1 {
  text-align: center;
}
.group-header th {
  font-size: 200%;
}
.sub-header th {
  font-size: 150%;
}
table, th, td {
  border: 1px solid black;
}
table {
  margin: 0 auto;
}
.severity {
  text-align: center;
  font-weight: bold;
  color: #000000;
}
.severity-Low .severity { background-color: #5fbb31; color: #000000; }
.severity-Medium .severity { background-color: #e9c600; color: #000000;}
.severity-High .severity { background-color: #ff8800;  color: #000000;}
.severity-Critical .severity { background-color: #e40000; color: #000000;}
.severity-UNKNOWN .severity { background-color: #747474; color: #000000; }
.severity-Low { background-color: #5fbb3160; color: #000000; }
.severity-Medium { background-color: #e9c60060; color: #000000; }
.severity-High { background-color: #ff880060; color: #000000; }
.severity-Critical { background-color: #e4000060; color: #000000; }
.severity-UNKNOWN { background-color: #74747460; color: #000000; }
table tr td:first-of-type {
  font-weight: bold;
}
.links a,
.links[data-more-links=on] a {
  display: block;
}
.links[data-more-links=off] a:nth-of-type(1n+5) {
  display: none;
}
a.toggle-more-links { cursor: pointer; }

body{
  background-color: LavenderBlush;
}

hr.dashed {
  border-top: 5px dashed #DC143C;
  margin: auto;
}
</style>
  <meta charset="utf-8">

  <title>Grype Scan Report</title>

  <meta name="description" content="The HTML5 Herald">
  <meta name="author" content="SitePoint">
    <style>
        table,th,td {border: 1px solid black;}
    </style>
  <script>
    window.onload = function() {
      document.querySelectorAll('td.links').forEach(function(linkCell) {
      var links = [].concat.apply([], linkCell.querySelectorAll('a'));
      [].sort.apply(links, function(a, b) {
        return a.href > b.href ? 1 : -1;
      });
      links.forEach(function(link, idx) {
        if (links.length > 3 && 3 === idx) {
          var toggleLink = document.createElement('a');
          toggleLink.innerText = "Toggle more links";
          toggleLink.href = "#toggleMore";
          toggleLink.setAttribute("class", "toggle-more-links");
          linkCell.appendChild(toggleLink);
        }
        linkCell.appendChild(link);
      });
    });
    document.querySelectorAll('a.toggle-more-links').forEach(function(toggleLink) {
      toggleLink.onclick = function() {
        var expanded = toggleLink.parentElement.getAttribute("data-more-links");
        toggleLink.parentElement.setAttribute("data-more-links", "on" === expanded ? "off" : "on");
        return false;
      };
    });
    };
  </script>
</head>

<body>
<h1>Grype Blueprint - ${release} - Scan Report</h1>
<h3 style="text-align: center;">This page contains the Grype MKS scan report for today, ${d.toDateString()} for the images given below.</h3>
<h4><u>Description</u></h4>
<p style="margin-right: 600px;">The First table is the count table which gives us an overview of the total number of Vulnerabilities present across all images grouped by severity</p>
<table style="width:100%; border: 1px solid black;">
  <tr>
    <th>Type</th>
    <th>Count</th>
    ##
  </tr>
  <tr>
    <th>Total</th>
    <th>%%%%</th>
  </tr>
</table>
  <br></br>
<p style="margin-right: 600px;"> The subsequent tables give us the Vulnerabilities present in OS packages for each image.</p>
<p style="margin-right: 600px;">Dividers have been used to differentiate one image scan report from the next</p>
<br/>
<br/>
<hr class="dashed"></hr>
 `;

let htmlBoilerplateEnd = `
 </body>
 </html>`;

let countJson = { Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 };
let countTable = [];
let scarray=[];
let subcount = { Critical: 0, High: 0, Medium: 0, Low: 0 };
for (let i=0; i < testJson.length; i++){
  if(testJson[i].matches.length!==0){
    subcount={ Critical: 0, High: 0, Medium: 0, Low: 0 };
    testJson[i].matches.forEach((item)=>{
      subcount[item.vulnerability.severity]+=1
    })
  } else {
    subcount={ Critical: 0, High: 0, Medium: 0, Low: 0 };
  }
  scarray.push(subcount)
}

const generateLinks = function (refs) {
  let res = [];
  refs.forEach((item) => {
    res.push(`<a target="_blank"href="${item}">${item}</a>`);
  });
  return res.join("\n\n");
};

let toAppend = [];
let i;
let j;
let counter = 0;

for (i = 0; i < testJson.length; i++) {
  if (testJson[i].hasOwnProperty("matches")) {
    counter = counter + testJson[i].matches.length;
    let tableHeaderString = `<br/><br/><br/><br/><p style="text-align: left; margin:auto;">This is the scan report for - <b style=""><u>${testJson[i].source.target.userInput}</u></b></p><br/><br/><table style="width:100%; border: 1px solid black; table-layout: fixed;overflow-wrap: break-word;">
    <tr>
    <th>CVE ID</th>
    <th>Package Name</th>
    <th>Current Version</th>
    <th>Fixed Version</th>
    <th>Severity</th>
    <th>Links</th>
    </tr>`;
    if (testJson[i].matches.length !== 0){
      toAppend.push(tableHeaderString);
      toAppend.push(`<h3 style = "text-align: left; margin: auto;">The number of Vulnerabilities in this image are:
      <p>================================================</p></h3>
      <h3>Critical:${JSON.stringify(scarray[i].Critical)} High:${JSON.stringify(scarray[i].High)} Medium:${JSON.stringify(scarray[i].Medium)} Low:${JSON.stringify(scarray[i].Low)}</h3><br/><br/>`)
      for (j = 0; j < testJson[i].matches.length; j++){
        let item = testJson[i].matches[j];
          toAppend.push(`<tr class="severity-${item.vulnerability.severity}">
            <th>${item.vulnerability.id}</th><th>${item.artifact.name}</th><th>${
            item.artifact.version
          }</th>
          <th>${item.vulnerability.fix.versions.length !== 0 ?item.vulnerability.fix.versions[0] : 'Fixes indeterminate' }</th>
          <th class="severity-${item.vulnerability.severity} severity">${
          item.vulnerability.severity
          }</th>
          
          <td class="links" style="text-align: left;" data-more-links="off">
          ${item.vulnerability.urls? generateLinks(
              item.vulnerability.urls
            ):"No References available yet"
          }</td>
        </tr>`);
        countJson[item.vulnerability.severity] = countJson[item.vulnerability.severity] + 1; 
      }
    }
    else{
      toAppend.push(`<br/><br/><p style="text-align: left; margin:auto;">This is the scan report for - <b>${testJson[i].source.target.userInput}</b></p>
      <br/><p style="text-align: left;">No Vulnerabilities are found for this Image</p>
      <h3>The number of Vulnerabilities in this image are:
      <p>===============================================</p></h3>
      <h3>Critical: 0 High: 0 Medium: 0 Low: 0</h3>
      <br/><br/><br/><hr class="dashed">`)
    }
    if (j === testJson[i].matches.length) {
    toAppend.push(`</table><br/><br/><br/><br/><hr class="dashed"><br/><br/>`);
    }
  }
}
for (key in countJson) {
  countTable.push(
    `<tr class="severity-${key}"><th class="severity">${key}</th><th>${countJson[key]}</th></tr>`
  );
}

console.log(release)

htmlBoilerplateStart = htmlBoilerplateStart + toAppend.join("");
+htmlBoilerplateEnd;
htmlBoilerplateStart = htmlBoilerplateStart.replace(
  new RegExp("##", "g"),
  countTable.join("").trim(",")
);
htmlBoilerplateStart = htmlBoilerplateStart.replace(
  new RegExp("%%%%", "g"),
  counter
);
fs.writeFileSync("grype-blueprint-release-report.html", htmlBoilerplateStart);
