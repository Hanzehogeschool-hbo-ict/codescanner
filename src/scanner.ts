import * as vscode from "vscode";
import * as fs from 'fs';
import { workspaceFolder } from "./functions";
import { round } from "./functions";
import { markdownToHtml } from "./md-to-html";
import { homedir } from "os";

var pluginPath = `${homedir}` + "/.vscode/extensions/mk2000.code-project-scanner-1.0.0/";

async function startOwasp(){
  // get work folder location
    var wf = undefined;
    if(vscode.workspace.workspaceFolders !== undefined) {
      wf = (vscode.workspace.workspaceFolders[0].uri.path).substring(1); // substring removes first "/" of the wf path           
    } 
    else {
        let message = "Working folder not found, open a folder an try again";
        vscode.window.showErrorMessage(message);
    }

    // start terminal with owasp dependency-check
    let terminal = vscode.window.createTerminal({
        name: "Code Project Scanner: Dependency-Check",
        //cwd: pluginPath,
        hideFromUser: false,
        shellPath: pluginPath + "dependency-check/bin/dependency-check.bat",
        shellArgs: `-s ${wf} -f JSON -o scanresults`,
        });

      terminal.show();
} 

export async function runScan(){
  startOwasp();
}

export function parseJson(){
  let wf = workspaceFolder();

  var output = "No results were found. Make sure to run the scan first.";
  var name, workspace, reportDate, dependencies, table, criticalCount, highCount, mediumCount, lowCount, noneCount, vulnerableCount, notVulnerableCount, dependenciesCount, vulnerablePercentage;
  name = workspace = reportDate = dependencies = "No result";
  table = "";
  vulnerableCount = notVulnerableCount = dependenciesCount = vulnerablePercentage = criticalCount = highCount = mediumCount = lowCount = 0;
  try {
    const resultFile  = fs.readFileSync(`${wf}` + "/scanresults/dependency-check-report.json", 'utf-8'); //fs.readFileSync(pluginPath + "dependency-check/scanresults/dependency-check-report.json", 'utf-8');
    const data = JSON.parse(resultFile);
    
    // projectinfo
    name = vscode.workspace.name;
    workspace = workspaceFolder();
    reportDate = new Date(data.projectInfo.reportDate).toLocaleString("nl-NL");

    // dependencies
    let dependenciesJson = data.dependencies;
    const dependenciesString = JSON.stringify(dependenciesJson);
    dependencies = JSON.parse(dependenciesString);

    // Initialise vulnerability properties
    var severity = "Unknown";
    var description = "There are no description available for this vulnerability.";
    var packageId = "Unknown";
    var packageUrl = "Unknown";

    // Initialise cvss properties
    var accessVector = "Unknown";
    var accessComplexity = "Unknown";
    var confidentialImpact = "Unknown";
    var integrityImpact = "Unknown";
    var availabilityImpact= "Unknown";

    var accessVectorDesc = "Unknown";
    var accessComplexityDesc = "Unknown";
    var confidentialImpactDesc = "Unknown";
    var integrityImpactDesc = "Unknown";
    var availabilityImpactDesc = "Unknown";

    // initialise project risk variables
    var projectRisk;
    var totRiskScore = new Array();
    var totRiskScoreSum = 0;

    var projectRiskConfHigh;
    var projectRiskConfLow;
    var totRiskScoreConfHigh = new Array();
    var totRiskScoreConfLow = new Array();
    var totRiskScoreSumConfHigh = 0;
    var totRiskScoreSumConfLow = 0;

    var projectRiskIntegHigh;
    var projectRiskIntegLow;
    var totRiskScoreIntegHigh = new Array();
    var totRiskScoreIntegLow = new Array();
    var totRiskScoreSumIntegHigh = 0;
    var totRiskScoreSumIntegLow = 0;

    var projectRiskAvailHigh;
    var projectRiskAvailLow;
    var totRiskScoreAvailHigh = new Array();
    var totRiskScoreAvailLow = new Array();
    var totRiskScoreSumAvailHigh = 0;
    var totRiskScoreSumAvailLow = 0;

    // Initialise maps
    const severityMap = new Map();
    severityMap.set("Low", 0);
    severityMap.set("Medium", 1);
    severityMap.set("High", 2);
    severityMap.set("Critical", 3);
    var highestSeverity = "Unknown";

    const cvssv2Map = new Map();
    cvssv2Map.set("N", 0);
    cvssv2Map.set("L", 1);
    cvssv2Map.set("H", 2);


    // Loop through found dependencies
    for(var index in dependencies)
    { 
      let fileName = dependencies[index].fileName;
      let filePath = dependencies[index].filePath;
      let virtual = dependencies[index].isVirtual; 
      
      let isVulnerable = true;  
      if (virtual === false){ isVulnerable = false; }
      
      table += "<tr>";
      table += "<td>" + fileName + "</td>";        
      if (isVulnerable === true){
        vulnerableCount += 1;
        
        try {
          description = dependencies[index].vulnerabilities[0].description;
          packageId = dependencies[index].packages[0].id;
          packageUrl = dependencies[index].packages[0].url;

        }
        catch {
        }        

        var descriptionArr = new Array();
        var values = new Array();
        var scores = new Array();        
        var cweArr = new Array();
        var referenceNames = new Array();


        try {
          var confImpact;
          var integImpact;
          var availImpact;
          var impactScore; 

          var accessVectorScore;
          var accessComplexityScore;
          var exploitScore;

          var baseScore;
          var adjustedImpact;
          var adjustedBaseScoreLow;
          var adjustedBaseScoreHigh;
          var riskScore;

          let i: number = 0;
          while (dependencies[index].vulnerabilities[i]) {
            let description = dependencies[index].vulnerabilities[i].description;
            descriptionArr.push(description);

            severity = dependencies[index].vulnerabilities[i].severity;
            severity = severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase(); // capitalize first letter, rest is lowercase

            for (let [key, value] of severityMap) {
              if (key === severity) {
                values.push(value);      
              }
            }

            let cvssv2 = dependencies[index].vulnerabilities[i].cvssv2; 

            // get CVSS properties  
            if (cvssv2 !== undefined){
              let score = cvssv2.score;
              let accessVectorCVSS = cvssv2.accessVector;
              let accessComplexityCVSS = cvssv2.accessComplexity;
              let confidentialImpactCVSS = cvssv2.confidentialImpact;
              let integrityImpactCVSS = cvssv2.integrityImpact;
              let availabilityImpactCVSS = cvssv2.availabilityImpact;

              if (accessVectorCVSS === "L"){
                accessVectorScore = 0.395;
                accessVector = "Local";
              } else if (accessVectorCVSS === "A"){
                accessVectorScore = 0.646;
                accessVector = "Adjecent Network";
              } else if (accessVectorCVSS === "N"){
                accessVectorScore = 1;
                accessVector = "Network";
              }

              if (accessComplexityCVSS === "H"){
                accessComplexityScore = 0.35;
                accessComplexity = "High";
              } else if (accessComplexityCVSS === "M"){
                accessComplexityScore = 0.61;
                accessComplexity = "Medium";
              } else if (accessComplexityCVSS === "L"){
                accessComplexityScore = 0.71;
                accessComplexity = "Low";
              }
              
              if (confidentialImpactCVSS === "N"){
                confImpact = 0;
                confidentialImpact = "None";
              } else if (confidentialImpactCVSS === "L"){
                confImpact = 0.275;
                confidentialImpact = "Partial";
              } else if (confidentialImpactCVSS === "H"){
                confImpact = 0.66;
                confidentialImpact = "Complete";
              }
              
              if (integrityImpactCVSS === "N"){
                integImpact = 0;
                integrityImpact = "None";
              } else if (integrityImpactCVSS === "L"){
                integImpact = 0.275;
                integrityImpact = "Partial";
              } else if (integrityImpactCVSS === "H"){
                integImpact = 0.66;
                integrityImpact = "Complete";
              }
              
              if (availabilityImpactCVSS === "N"){
                availImpact = 0;
                availabilityImpact = "None";
              } else if (availabilityImpactCVSS === "L"){
                availImpact = 0.275;
                availabilityImpact = "Partial";
              } else if (availabilityImpactCVSS === "H"){
                availImpact = 0.66;
                availabilityImpact = "Complete";
              }
              scores.push(score);  
            } 

            let cwes = dependencies[index].vulnerabilities[i].cwes;
            if (cwes.length !== 0){
              for (let cwe of cwes) {
                cweArr.push(cwe);
              }
            }

            let referenceSource = dependencies[index].vulnerabilities[i].references[0].source;
            let referenceName = dependencies[index].vulnerabilities[i].references[0].name;
            let referenceUrl = dependencies[index].vulnerabilities[i].references[0].url;

            if (referenceName.includes("\n- ")){
              for (let item of referenceName.split("\n- ")){
                referenceNames.push(item.replace("- ", "")); // remove first "- "
              } 
            } else {
              referenceNames.push(referenceName);
            } 
            i++;
          }
        } catch {
          descriptionArr.push(description);
        }

        if (accessVectorScore !== undefined && accessComplexityScore !== undefined){
          exploitScore = 20 * accessVectorScore * accessComplexityScore * 0.704;
        } else {
          exploitScore = "Unknown";
        }

        let adjustedConfImpactHigh;
        let adjustedConfImpactLow;
        let adjustedIntegImpactHigh;
        let adjustedIntegImpactLow;
        let adjustedAvailImpactHigh;
        let adjustedAvailImpactLow;

        let adjustedBaseScoreConfHigh;
        let adjustedBaseScoreConfLow;
        let adjustedBaseScoreIntegHigh;
        let adjustedBaseScoreIntegLow;
        let adjustedBaseScoreAvailHigh;
        let adjustedBaseScoreAvailLow;

        if(confImpact !== undefined && integImpact !== undefined && availImpact !== undefined){
          impactScore = 10.41*(1-(1-confImpact)*(1-integImpact)*(1-availImpact));

          adjustedConfImpactHigh = Math.min(10,10.41*(1-(1-confImpact*1.51)*(1-integImpact*1)*(1-availImpact*1)));
          adjustedConfImpactLow = Math.min(10,10.41*(1-(1-confImpact*0.5)*(1-integImpact*1)*(1-availImpact*1)));

          adjustedIntegImpactHigh = Math.min(10,10.41*(1-(1-confImpact*1)*(1-integImpact*1.51)*(1-availImpact*1)));
          adjustedIntegImpactLow = Math.min(10,10.41*(1-(1-confImpact*1)*(1-integImpact*0.5)*(1-availImpact*1)));

          adjustedAvailImpactHigh = Math.min(10,10.41*(1-(1-confImpact*1)*(1-integImpact*1)*(1-availImpact*1.51)));
          adjustedAvailImpactLow = Math.min(10,10.41*(1-(1-confImpact*1)*(1-integImpact*1)*(1-availImpact*0.5)));

        } else {
          impactScore = adjustedImpact = "Unknown";
        }
        if(typeof impactScore === "number" && typeof exploitScore === "number"){
          if (impactScore === 0){
            baseScore = (((0.6*impactScore)+(0.4*exploitScore)-1.5)*0);

          } else {
            baseScore = (((0.6*impactScore)+(0.4*exploitScore)-1.5)*1.176);
            if (adjustedConfImpactHigh !== undefined && adjustedConfImpactLow !== undefined && adjustedIntegImpactHigh !== undefined && adjustedIntegImpactLow !== undefined && adjustedAvailImpactHigh !== undefined && adjustedAvailImpactLow !== undefined){
              adjustedBaseScoreConfHigh = round((((0.6*adjustedConfImpactHigh) + (0.4*exploitScore)-1.5)*1.176),1);
              adjustedBaseScoreConfLow =  round((((0.6*adjustedConfImpactLow) + (0.4*exploitScore)-1.5)*1.176),1);
              adjustedBaseScoreIntegHigh = round((((0.6*adjustedIntegImpactHigh) + (0.4*exploitScore)-1.5)*1.176),1);
              adjustedBaseScoreIntegLow =  round((((0.6*adjustedIntegImpactLow) + (0.4*exploitScore)-1.5)*1.176),1);
              adjustedBaseScoreAvailHigh = round((((0.6*adjustedAvailImpactHigh) + (0.4*exploitScore)-1.5)*1.176),1);
              adjustedBaseScoreAvailLow =  round((((0.6*adjustedAvailImpactLow) + (0.4*exploitScore)-1.5)*1.176),1);
            }
          }
        } else {
          baseScore = "Unknown";
        }
 
        let descSet = new Set(descriptionArr);
        descriptionArr = Array.from(descSet.values());

        // get key based on value
        for (let [key, value] of cvssv2Map.entries()) {
          if (key === "N"){
            key = "None";
          } else if (key === "L"){
            key = "Low";
          } else if (key === "M"){
            key = "Medium";  
          } else if (key === "H"){
            key = "High";
          } else {
            key = "Unknown";
          }

          if (accessVector === "Local"){
            accessVectorDesc = "a vulnerability exploitable with only local access requires the attacker to have either physical access to the vulnerable system or a local (shell) account. Examples of locally exploitable vulnerabilities are peripheral attacks such as Firewire/USB DMA attacks, and local privilege escalations (e.g., sudo).";
          } else if (accessVector === "Adjecent Network"){
            accessVectorDesc = "a vulnerability exploitable with adjacent network access requires the attacker to have access to either the broadcast or collision domain of the vulnerable software.  Examples of local networks include local IP subnet, Bluetooth, IEEE 802.11, and local Ethernet segment.";
          } else if (accessVector === "Network"){
            accessVectorDesc = "a vulnerability exploitable with network access means the vulnerable software is bound to the network stack and the attacker does not require local network access or local access. Such a vulnerability is often termed 'remotely exploitable'. An example of a network attack is an RPC buffer overflow.";
          } else {
            accessVectorDesc = "DESCRIPTION COULD NOT BE FOUND, PLEASE BE CAUTIOUS!";
          }

          if (accessComplexityDesc){
            if (accessComplexity === "Low") {
              accessComplexityDesc = "specialized access conditions do not exist. Examples are: ";
              accessComplexityDesc += "<ul>";
              accessComplexityDesc += "<li>The affected product requires access to a wide range of systems and users, possibly anonymous and untrusted.</li>";
              accessComplexityDesc += "<li>The affected configuration is default or commonly used in practice.</li>";
              accessComplexityDesc += "<li>The attack can be performed manually and requires little skill or additional information gathering.</li>";
              accessComplexityDesc += "</ul>";
            } else if (accessComplexity === "Medium") {
              accessComplexityDesc = "The access conditions are somewhat specialized. Examples are: ";
              accessComplexityDesc += "<ul>";
              accessComplexityDesc += "<li>The attacking party is limited to a group of systems or users at some level of authorization, possibly untrusted.</li>";
              accessComplexityDesc += "<li>Some information must be gathered before a successful attack can be launched.</li>";
              accessComplexityDesc += "<li>The affected configuration is non-default.</li>";
              accessComplexityDesc += "<li>The attack requires a small amount of social engineering that might occasionally fool cautious users (e.g., phishing attacks that modify a web browsers status bar to show a false link.</li>";
              accessComplexityDesc += "</ul>";
            } else if (accessComplexity === "High") {
              accessComplexityDesc = "specialized access conditions exist. Examples are: ";
              accessComplexityDesc += "<ul>";
              accessComplexityDesc += "<li>The attacking part must already have elevated privileges or spoof additional systems in addition to the attacking system.</li>";
              accessComplexityDesc += "<li>The attack depends on social engineering methods that would be easily detected by knowledgeable people. For example, the victim must perform several suspicious or atypical actions.</li>";
              accessComplexityDesc += "<li>The vulnerable configuration is seen very rarely in practice.</li>";
              accessComplexityDesc += "<li>If a race condition exists, the window is very narrow.</li>";
              accessComplexityDesc += "</ul>";
            } else {
              accessComplexityDesc = "DESCRIPTION COULD NOT BE FOUND, PLEASE BE CAUTIOUS!";
            }
          }

          if (confidentialImpact === "None") {
            confidentialImpactDesc = "there is no impact to the condifentiality of the system";
          } else if (confidentialImpact === "Partial") {
            confidentialImpactDesc = "there is considerable informational disclosure. Access to some system files is possible, but the attacker does not have control over what is obtained, or the scope of the loss is constrained. An example is a vulnerability that divulges only certain tables in a database.";
          } else if (confidentialImpact === "Complete") {
            confidentialImpactDesc = "there is total information disclosure, resulting in all system files being revealed. The attacker is able to read all of the system's data (memory, files, etc.)";
          } else {
            confidentialImpactDesc = "DESCRIPTION COULD NOT BE FOUND, PLEASE BE CAUTIOUS!";
          }

          if (integrityImpact === "None") {
            integrityImpactDesc = "there is no impact to the integrity of the system";
          } else if (integrityImpact === "Partial") {
            integrityImpactDesc = "modification of some system files or information is possible, but the attacker does not have control over what can be modified, or the scope of what the attacker can affect is limited. For example, system or application files may be overwritten or modified, but either the attacker has no control over which files are affected or the attacker can modify files within only a limited context or scope.";
          } else if (integrityImpact === "Complete") {
            integrityImpactDesc = "there is a total compromise of system integrity. There is a complete loss of system protection, resulting in the entire system being compromised. The attacker is able to modify any files on the target system.";
          } else {
            integrityImpactDesc = "DESCRIPTION COULD NOT BE FOUND, PLEASE BE CAUTIOUS!";
          }
          if (availabilityImpact === "None") {
            availabilityImpactDesc = "there is no impact to the availability of the system";
          } else if (availabilityImpact === "Partial") {
            availabilityImpactDesc= "there is reduced performance or interruptions in resource availability. An example is a network-based flood attack that permits a limited number of successful connections to an Internet service.";
          } else if (availabilityImpact === "Complete") {
            availabilityImpactDesc = "there is a total shutdown of the affected resource. The attacker can render the resource completely unavailable.";
          } else {
            availabilityImpactDesc = "DESCRIPTION COULD NOT BE FOUND, PLEASE BE CAUTIOUS!";
          }
        } 

        let cweSet = new Set(cweArr);
        cweArr = Array.from(cweSet.values());
        if (cweArr.length === 0) {
          cweArr.push("Unknown");
        }

        values.sort(); // sort to get highest value as last value
        let highestSeverityVal = values[values.length -1]; // get last/highest value
        let lowestSeverityval = values[0];
        // get key based on value
        for (let [key, value] of severityMap.entries()) {
          if (value === highestSeverityVal){
            highestSeverity = key;
          }
        }
        
        if (typeof baseScore === "number"){
          totRiskScore.push(baseScore);
          totRiskScoreSum += baseScore;
        }

        if (typeof adjustedBaseScoreConfHigh === "number"){
          totRiskScoreConfHigh.push(adjustedBaseScoreConfHigh);
          totRiskScoreSumConfHigh += adjustedBaseScoreConfHigh;
        }
        if (typeof adjustedBaseScoreConfLow === "number"){
          totRiskScoreConfLow.push(adjustedBaseScoreConfLow);
          totRiskScoreSumConfLow += adjustedBaseScoreConfLow;
        }

        if (typeof adjustedBaseScoreIntegHigh === "number"){
          totRiskScoreIntegHigh.push(adjustedBaseScoreIntegHigh);
          totRiskScoreSumIntegHigh += adjustedBaseScoreIntegHigh;
        }
        if (typeof adjustedBaseScoreIntegLow === "number"){
          totRiskScoreIntegLow.push(adjustedBaseScoreIntegLow);
          totRiskScoreSumIntegLow += adjustedBaseScoreIntegLow;
        }

        if (typeof adjustedBaseScoreAvailHigh === "number"){
          totRiskScoreAvailHigh.push(adjustedBaseScoreAvailHigh);
          totRiskScoreSumAvailHigh += adjustedBaseScoreAvailHigh;
        }
        if (typeof adjustedBaseScoreAvailLow === "number"){
          totRiskScoreAvailLow.push(adjustedBaseScoreAvailLow);
          totRiskScoreSumAvailLow += adjustedBaseScoreAvailLow;
        }

        
        let highestScore: any = Math.max.apply(Math, scores);
        let lowestScore: any = Math.min.apply(Math, scores);
        // let avgScore: any = parseFloat((scoresSum / scores.length).toFixed(1))+"/10";


        if (scores.length === 0){
          highestScore = "Unknown";
          lowestScore = "Unknown";          
        }

        riskScore = baseScore;
        if (baseScore === "Unknown") {
          riskScore = highestScore;
        }
        riskScore = round(riskScore,1);

        if (riskScore > 0 && riskScore < 4){
          severity = "Low";
        } else if (riskScore >= 4 && riskScore < 7){
          severity = "Medium";
        } else if (riskScore >= 7 && riskScore < 9){
          severity = "High";
        } else if (riskScore >= 9){
          severity = "Critical";
        } else {
          severity = "Unknown";
        }

        // create modal per vulnerable dependency
        let modalId = "modal" + vulnerableCount;
        table += "<div id='"+ modalId +"' class='modal'><div class='modal-content'>";      
        table += "<span onclick='document.getElementById(`"+ modalId +"`).style.display=`none`'class='close'>&times;</span>";
        
        table += "<h1><b>"+ fileName +"</b></h1>";         
        table += "<p><b>Location: </b>"+ filePath+"</p><br>";
        
        table += "<h2><b>Vulnerability Info</b></h2>";
        table += "<p><i>This section indicates the overall risk of using the specific dependency.</i></p>";
        if (typeof impactScore === "number"){
          table += "<p><b>Impact score: </b>"+ round(impactScore,1) +"</p>";
          table += "<p><i>The higher the impact score, the greater the negative influence when a successful attack is performed </i></p>";
        } else {
          table += "<p><b>Impact score: </b>"+ impactScore +"</p>";
        }
        if (typeof exploitScore === "number"){
          table += "<p><b>Exploit score: </b>"+ round(exploitScore,1) +"</p>";
          table += "<p><i>The higher the exploit score, the easier an attack could be successfully executed.</i></p>";
        } else {
          table += "<p><b>Exploit score: </b>"+ exploitScore +"</p>";
        }

        table += "<p><b>Risk score: </b>"+ riskScore +"</p>";
        table += "<p><b>Risk: </b>"+ severity +"</p>";
        table += "<p><i>The higher the risk, the more it is recommended to solve the vulnerability that has been found. The higher the risk, the sooner the risk should be addressed to prevent the execution of a successfull attack.</i></p>";
        table += "<br>";

        table += "<h3><b>Access Vector</b></h3>";
        table += "<p><i>This metric indicates via what way an attacker can intrude in a system to be able to perform an attack.</i></p>";
        table += "<p><u>Value: </u>"+ accessVector +"</p>";
        table += "<p><i>The greater the distance at which a successful attack is possible between the attacker and the target , the greater the risk. Example: Local access is closer to the target, so the risk is less than when the access vector is network, which is further from the target. </i></p>";
        table += "<p><u>Explanation: </u> The access vector is "+ accessVector + ", this means that " + accessVectorDesc +"</p><br>";

        table += "<h3><b>Access Complexity</b></h3>";
        table += "<p><i>This metric indicates the complexity of an attack to be successful.</i></p>";
        table += "<p><u>Value: </u>"+ accessComplexity +"</p>";
        table += "<p><i>The lower the complexity, the easier an attack could be successfully executed</i></p>";
        table += "<p><u>Explanation: </u> The access complexity is rated as "+ accessComplexity + ", this means that " + accessComplexityDesc +"</p><br>";

        table += "<h3><b>Confidential Impact</b></h3>";
        table += "<p><i>This metric indicates the impact on the confidentiality when an attack is successfully executed.</i></p>";
        table += "<p><u>Value: </u>"+ confidentialImpact +"</p>";
        table += "<p><i>The higher the impact, the greater the negative influence when a successful attack is performed</i></p>";
        table += "<p><u>Explanation: </u> The confidential impact is rated as "+ confidentialImpact + ", this means that " + confidentialImpactDesc +"</p><br>";
        table += "<p><u>Risk score without priorities: </u>"+ riskScore +"</p>";
        table += "<p><u>Risk score priority to confidentiality: </u>"+ adjustedBaseScoreConfHigh +"</p>";
        table += "<p><u>Risk score unimportance to confidentiality: </u>"+ adjustedBaseScoreConfLow +"</p><br>";    

        table += "<h3><b>Integrity Impact</b></h3>";
        table += "<p><i>This metric indicates the impact on the integrity when an attack is successfully executed.</i></p>";
        table += "<p><u>Value: </u>"+ integrityImpact +"</p>";
        table += "<p><i>The higher the impact, the greater the negative influence when a successful attack is performed</i></p>";
        table += "<p><u>Explanation: </u> The integrity impact is rated as "+ integrityImpact + ", this means that " + integrityImpactDesc +"</p><br>";
        table += "<p><u>Risk score without priorities: </u>"+ riskScore +"</p>";
        table += "<p><u>Risk score priority to integrity: </u>"+ adjustedBaseScoreIntegHigh +"</p>";
        table += "<p><u>Risk score unimportance to integrity: </u>"+ adjustedBaseScoreIntegLow +"</p><br>";    

        table += "<h3><b>Availability Impact</b></h3>";
        table += "<p><i>This metric indicates the impact on the availability when an attack is successfully executed.</i></p>";
        table += "<p><u>Value: </u>"+ availabilityImpact +"</p>";
        table += "<p><i>The higher the impact, the greater the negative influence when a successful attack is performed</i></p><br>";
        table += "<p><u>Explanation: </u> The availability impact is rated as "+ availabilityImpact + ", this means that " + availabilityImpactDesc +"</p>";
        table += "<p><u>Risk score without priorities: </u>"+ riskScore +"</p>";
        table += "<p><u>Risk score priority to availability: </u>"+ adjustedBaseScoreAvailHigh +"</p>";
        table += "<p><u>Risk score unimportance to availability: </u>"+ adjustedBaseScoreAvailLow +"</p><br>";    

        table += "<h2><b>Descriptions</b></h2>";
        table += "<p><i>This section shows all descriptions about the vulnerability that have been found.</i></p>";
        for (let i = 0; i < descriptionArr.length; i++) {
          let desc = descriptionArr[i];
          let sum = i + 1;
          table += "<p><b>Description " + sum + ": </b></p>";
          try {
            table += markdownToHtml(desc);
          } catch {
            table += desc;
          } 
        }
        table += "<br>";
        table += "<br>";
        table += "<h2><b>Weaknesses (CWES)</b></h2>";
        table += "<p><i>This section shows CWE-entries. Clicking on a CWE shows the weakness that has been found, including examples to help understand the problem.</i></p>";
        table += "<ul>";
        for (let item of cweArr){
          if (item !== "Unknown"){
            let cweNum = item.replace("CWE-", "");
            let url = "https://cwe.mitre.org/data/definitions/" + cweNum + ".html";
            table += "<li><a href='" + url + "'>"+item+"</a></li>";
          } else {
            table += "<li>"+ item + "</li>";
          }
        }
        table += "</ul>";
        table += "<br>";

        table += "<h2><b>References</b></h2>";
        table += "<p><i>This section shows the references of the found vulnerability. These references contain comprehensive information about the vulnerability, sometimes including a solution or patch.</i></p>";
        table += "<ul>";
        for (let item of referenceNames){
          table += "<li><a href='" + item + "'>"+item+"</a></li>";
        }
        table += "</ul>";
        table += "<br>";

        table += "<h2><b>Package Info</b></h2>";
        table += "<p><b>Package : </b>"+ packageId +"</p>";
        table += "<p><b>Package info: </b><a href="+ packageUrl +">Learn More</a> (opens in browser)</p><br>";

        table += "</div></div>";
        table += "<td><b>"+ "Yes" + "</b></td>";

        if (severity === "Critical"){
          criticalCount += 1;
          table += "<td style='background-color: firebrick'><span style='color: white'><b>" + severity.toUpperCase() + "</b></span></td>";
        } else if (severity === "High"){
          highCount += 1;
          table += "<td style='background-color: red'><span style='color: white'>" + severity + "</span></td>";
        } else if (severity === "Medium"){
          mediumCount += 1;
          table += "<td style='background-color: orange'><span style='color: white'>" + severity + "</span></td>";
        } else if (severity === "Low"){
          lowCount += 1;
          table += "<td style='background-color: yellow'><span style='color: black'>" + severity + "</span></td>";
        } else if (severity) {
          table += "<td>" + severity + "</td>";
        } else {
          table += "<td>Unknown</td>";
        }
        table += "<td>" + riskScore + "/10</td>"; // comment
        table += "<td><button onclick='document.getElementById(`"+ modalId +"`).style.display=`block`'>Show Details</button></td>";
        table += "</tr>";        

      } else {
        table += "<td>"+ "No" + "</td>";
        table += "<td style='background-color: chartreuse'><span style='color: white'>None</span></td>";
        table += "<td>"+ "None" + "</td>";
        table += "</tr>";
        notVulnerableCount += 1;
      }      
    } 

    dependenciesCount = vulnerableCount + notVulnerableCount;
    vulnerablePercentage = ((vulnerableCount / dependenciesCount) *100).toPrecision(3);
    output = "";

    projectRisk = (totRiskScoreSum / totRiskScore.length)*(vulnerableCount / dependenciesCount);
    if (projectRisk > 0 && projectRisk < 4){
      projectRisk = projectRisk.toFixed(1) + "- Low";
    } else if (projectRisk >= 4 && projectRisk < 7){
      projectRisk = projectRisk.toFixed(1) + "- Medium";
    } else if (projectRisk >= 7 && projectRisk < 9){
      projectRisk = projectRisk.toFixed(1) + "- High";
    } else if (projectRisk >= 9){
      projectRisk = projectRisk.toFixed(1) + "- Critical";
    } else if (projectRisk === 0) {
      projectRisk = projectRisk.toFixed(1) + "- None";
    } else {
      projectRisk = "Unknown";
    }
        
    projectRiskConfHigh = (totRiskScoreSumConfHigh / totRiskScoreConfHigh.length)*(vulnerableCount / dependenciesCount);
    if (projectRiskConfHigh > 0 && projectRiskConfHigh  < 4){
      projectRiskConfHigh  = projectRiskConfHigh.toFixed(1) + "- Low";
    } else if (projectRiskConfHigh  >= 4 && projectRiskConfHigh  < 7){
      projectRiskConfHigh  = projectRiskConfHigh.toFixed(1) + "- Medium";
    } else if (projectRiskConfHigh  >= 7 && projectRiskConfHigh  < 9){
      projectRiskConfHigh  = projectRiskConfHigh.toFixed(1) + "- High";
    } else if (projectRiskConfHigh  >= 9){
      projectRiskConfHigh  = projectRiskConfHigh.toFixed(1) + "- Critical";
    } else if (projectRiskConfHigh  === 0) {
      projectRiskConfHigh  = projectRiskConfHigh.toFixed(1) + "- None";
    } else {
      projectRiskConfHigh  = "Unknown";
    }

    projectRiskConfLow = (totRiskScoreSumConfLow / totRiskScoreConfLow.length)*(vulnerableCount / dependenciesCount);
    if (projectRiskConfLow > 0 && projectRiskConfLow  < 4){
      projectRiskConfLow = projectRiskConfLow .toFixed(1) + "- Low";
    } else if (projectRiskConfLow  >= 4 && projectRiskConfLow  < 7){
      projectRiskConfLow  = projectRiskConfLow.toFixed(1) + "- Medium";
    } else if (projectRiskConfLow  >= 7 && projectRiskConfLow  < 9){
      projectRiskConfLow = projectRiskConfLow.toFixed(1) + "- High";
    } else if (projectRiskConfLow >= 9){
      projectRiskConfLow  = projectRiskConfLow.toFixed(1) + "- Critical";
    } else if (projectRiskConfLow === 0) {
      projectRiskConfLow  = projectRiskConfLow.toFixed(1) + "- None";
    } else {
      projectRiskConfLow  = "Unknown";
    }    

    projectRiskIntegHigh = (totRiskScoreSumIntegHigh / totRiskScoreIntegHigh.length)*(vulnerableCount / dependenciesCount);
    if (projectRiskIntegHigh > 0 && projectRiskIntegHigh  < 4){
      projectRiskIntegHigh  = projectRiskIntegHigh.toFixed(1) + "- Low";
    } else if (projectRiskIntegHigh  >= 4 && projectRiskIntegHigh  < 7){
      projectRiskIntegHigh  = projectRiskIntegHigh.toFixed(1) + "- Medium";
    } else if (projectRiskIntegHigh  >= 7 && projectRiskIntegHigh  < 9){
      projectRiskIntegHigh  = projectRiskIntegHigh.toFixed(1) + "- High";
    } else if (projectRiskIntegHigh  >= 9){
      projectRiskIntegHigh  = projectRiskIntegHigh.toFixed(1) + "- Critical";
    } else if (projectRiskIntegHigh  === 0) {
      projectRiskIntegHigh  = projectRiskIntegHigh.toFixed(1) + "- None";
    } else {
      projectRiskIntegHigh  = "Unknown";
    }

    projectRiskIntegLow = (totRiskScoreSumIntegLow / totRiskScoreIntegLow.length)*(vulnerableCount / dependenciesCount);
    if (projectRiskIntegLow > 0 && projectRiskIntegLow  < 4){
      projectRiskIntegLow = projectRiskIntegLow .toFixed(1) + "- Low";
    } else if (projectRiskIntegLow  >= 4 && projectRiskIntegLow  < 7){
      projectRiskIntegLow  = projectRiskIntegLow.toFixed(1) + "- Medium";
    } else if (projectRiskIntegLow  >= 7 && projectRiskIntegLow  < 9){
      projectRiskIntegLow  = projectRiskIntegLow.toFixed(1) + "- High";
    } else if (projectRiskIntegLow >= 9){
      projectRiskIntegLow  = projectRiskIntegLow.toFixed(1) + "- Critical";
    } else if (projectRiskIntegLow  === 0) {
      projectRiskIntegLow  = projectRiskIntegLow.toFixed(1) + "- None";
    } else {
      projectRiskIntegLow  = "Unknown";
    }
    
    projectRiskAvailHigh = (totRiskScoreSumAvailHigh / totRiskScoreAvailHigh.length)*(vulnerableCount / dependenciesCount);
    if (projectRiskAvailHigh > 0 && projectRiskAvailHigh  < 4){
      projectRiskAvailHigh  = projectRiskAvailHigh.toFixed(1) + "- Low";
    } else if (projectRiskAvailHigh  >= 4 && projectRiskAvailHigh  < 7){
      projectRiskAvailHigh  = projectRiskAvailHigh.toFixed(1) + "- Medium";
    } else if (projectRiskAvailHigh  >= 7 && projectRiskAvailHigh  < 9){
      projectRiskAvailHigh  = projectRiskAvailHigh.toFixed(1) + "- High";
    } else if (projectRiskAvailHigh  >= 9){
      projectRiskAvailHigh  = projectRiskAvailHigh.toFixed(1) + "- Critical";
    } else if (projectRiskAvailHigh  === 0) {
      projectRiskAvailHigh  = projectRiskAvailHigh.toFixed(1) + "- None";
    } else {
      projectRiskAvailHigh  = "Unknown";
    }
    
    projectRiskAvailLow = (totRiskScoreSumAvailLow / totRiskScoreAvailLow.length)*(vulnerableCount / dependenciesCount);
    if (projectRiskAvailLow > 0 && projectRiskAvailLow  < 4){
      projectRiskAvailLow = projectRiskAvailLow .toFixed(1) + "- Low";
    } else if (projectRiskAvailLow  >= 4 && projectRiskAvailLow  < 7){
      projectRiskAvailLow  = projectRiskAvailLow.toFixed(1) + "- Medium";
    } else if (projectRiskAvailLow  >= 7 && projectRiskAvailLow  < 9){
      projectRiskAvailLow  = projectRiskAvailLow.toFixed(1) + "- High";
    } else if (projectRiskAvailLow >= 9){
      projectRiskAvailLow  = projectRiskAvailLow.toFixed(1) + "- Critical";
    } else if (projectRiskAvailLow  === 0) {
      projectRiskAvailLow  = projectRiskAvailLow.toFixed(1) + "- None";
    } else {
      projectRiskAvailLow  = "Unknown";
    }

    noneCount = (dependenciesCount - vulnerableCount);
  } catch {
    let message = "Failed loading results, make sure to run the scan first.";
    vscode.window.showErrorMessage(message);
  }
  return {name, workspace, reportDate, dependencies, table, criticalCount, highCount, mediumCount, lowCount, noneCount, vulnerableCount, notVulnerableCount, dependenciesCount, vulnerablePercentage,projectRisk,projectRiskConfHigh,projectRiskConfLow,projectRiskIntegHigh,projectRiskIntegLow,projectRiskAvailHigh,projectRiskAvailLow, output};
}