import * as vscode from "vscode";
import { getNonce } from "./functions";
import { parseJson } from "./scanner";

// Based on template that microsoft provides

export class WebViewPanel {
  /**
   * Track the currently panel. Only allow a single panel to exist at a time.
   */
  public static currentPanel: WebViewPanel | undefined;

  public static readonly viewType = "Results-Dependency-Check";

  private readonly _panel: vscode.WebviewPanel;
  private readonly _extensionUri: vscode.Uri;
  private _disposables: vscode.Disposable[] = [];

  public static createOrShow(extensionUri: vscode.Uri) {
    const column = vscode.window.activeTextEditor
      ? vscode.window.activeTextEditor.viewColumn
      : undefined;

    // If we already have a panel, show it.
    if (WebViewPanel.currentPanel) {
      WebViewPanel.currentPanel._panel.reveal(column);
      WebViewPanel.currentPanel._update();
      return;
    }

    // Otherwise, create a new panel.
    const panel = vscode.window.createWebviewPanel(
      WebViewPanel.viewType,
      "Results Dependency Check",
      column || vscode.ViewColumn.One,
      {
        // Enable javascript in the webview
        enableScripts: true,

        // And restrict the webview to only loading content from our extension's `media` directory.
        localResourceRoots: [
          vscode.Uri.joinPath(extensionUri, "media"),
          vscode.Uri.joinPath(extensionUri, "media/compiled"),
        ],
      }
    );

    WebViewPanel.currentPanel = new WebViewPanel(panel, extensionUri);
  }

  public static kill() {
    WebViewPanel.currentPanel?.dispose();
    WebViewPanel.currentPanel = undefined;
  }

  public static revive(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
    WebViewPanel.currentPanel = new WebViewPanel(panel, extensionUri);
  }

  private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
    this._panel = panel;
    this._extensionUri = extensionUri;

    // Set the webview's initial html content
    this._update();

    // Listen for when the panel is disposed
    // This happens when the user closes the panel or when the panel is closed programatically
    this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

  }

  public dispose() {
    WebViewPanel.currentPanel = undefined;

    // Clean up our resources
    this._panel.dispose();

    while (this._disposables.length) {
      const x = this._disposables.pop();
      if (x) {
        x.dispose();
      }
    }
  }

  private async _update() {
    const webview = this._panel.webview;

    this._panel.webview.html = this._getHtmlForWebview(webview);
    webview.onDidReceiveMessage(async (data) => {
      switch (data.type) {
        case "onInfo": {
          if (!data.value) {
            return;
          }
          vscode.window.showInformationMessage(data.value);
          break;
        }
        case "onError": {
          if (!data.value) {
            return;
          }
          vscode.window.showErrorMessage(data.value);
          break;
        }
      }
    });
  }

  private _getHtmlForWebview(webview: vscode.Webview) {
    const scriptUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media/compiled", "results.js")      
    );

    // Uri to load styles into webview
    const stylesResetUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "reset.css")
    );
    const stylesMainUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "vscode.css")
    );
    const styleMainUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "custom.css")
    );

    // Use a nonce to only allow specific scripts to be run
    const nonce = getNonce();
    var {
      name,
      workspace,
      reportDate,
      dependencies,
      table,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      noneCount,
      vulnerableCount,
      notVulnerableCount,
      dependenciesCount,
      vulnerablePercentage,
      projectRisk,
      projectRiskConfHigh,
      projectRiskConfLow,
      projectRiskIntegHigh,
      projectRiskIntegLow,
      projectRiskAvailHigh,
      projectRiskAvailLow,
      output
    } = parseJson();

    return `
          <!DOCTYPE html>
	        <html lang="en">
	        <head>
	          <meta charset="UTF-8">
            
		        <meta name="viewport" content="width=device-width, initial-scale=1.0">
		        <link href="${stylesResetUri}" rel="stylesheet">
		        <link href="${stylesMainUri}" rel="stylesheet"> 
            <link href="${styleMainUri}" rel="stylesheet"> 
	        </head>
          <script src="${scriptUri}" nonce="${nonce}"></script>
          <body>
            <h1>Scan Results</h1>
            <h2 class="whitespace-top">General</h2>
            <b>Project name: </b>${name}<br>
            <b>Project location: </b>${workspace}<br>
            <b>Report date: </b>${reportDate}<br>
            <h2 class="whitespace-top">Summary</h2>
            <b>No. of dependencies: </b>${dependenciesCount}<br>
            <b>No. of total vulnerable dependencies: </b>${vulnerableCount}<br>            
            <b>${vulnerablePercentage}%</b> of the dependencies are vulnerable.<br>

            <h3 class="whitespace-top">Project risk</h3>
            <i>The project risk is based on all dependencies including the none vulnerable dependencies. The higher the project risk the more vulnerable a project is.</i><br>
            <b>Project risk: </b>${projectRisk}<br>
            <b>Project risk priority to confidentiality: </b>${projectRiskConfHigh}<br>
            <b>Project risk unimportance to confidentiality: </b>${projectRiskConfLow}<br>
            <b>Project risk priority to integrity: </b>${projectRiskIntegHigh}<br>
            <b>Project risk unimportance to integrity: </b>${projectRiskIntegLow}<br>
            <b>Project risk priority to availability: </b>${projectRiskAvailHigh}<br>
            <b>Project risk unimportance to availability: </b>${projectRiskAvailLow}<br>

            
            <h3 class="whitespace-top">No. of dependencies per risk level</h3>
            <b>Critical: </b>${criticalCount}<br>
            <b>High: </b>${highCount}<br>
            <b>Medium: </b>${mediumCount}<br>
            <b>Low: </b>${lowCount}<br>
            <b>None: </b>${noneCount}<br>
            
            <h2 class="whitespace-top">Dependencies</h2>
            <p>This section shows all the dependencies that were found.</p> 
            <br>           

            <div class=filter-settings>    
              <label for='filter0'><input type="radio"  id="filter0" name="filter" value="yes" onclick="filterTable(1,'filter0')">Show vulnerable only</label>
              <label for='filter1'><input type="radio" id="filter1" name="filter" value="no" onclick="filterTable(1,'filter1')">Show not vulnerable only</label>
              <label for='risk0'><input type="radio" id="risk0" name="filter" value="CRITICAL" onclick="filterTable(2,'risk0')">Show Critical risk only</label>
              <label for='risk1'><input type="radio" id="risk1" name="filter" value="High" onclick="filterTable(2,'risk1')">Show High risk only</label>
              <label for='risk2'><input type="radio" id="risk2" name="filter" value="Medium" onclick="filterTable(2,'risk2')">Show Medium risk only</label>
              <label for='risk3'><input type="radio" id="risk3" name="filter" value="Low" onclick="filterTable(2,'risk3')">Show Low risk only</label>
            </div><br>


            <div class="sort-settings">
              <a onclick="sortTable(0)">Sort alphabetically</a> | 
              <a onclick="sortTable(1)">Sort vulnerable status</a> | 
              <a onclick="sortTable(3)">Sort risk score</a>

            </div>

            <table class="whitespace-top" id="table">
              <tr>                
                <th>Dependency</th>
                <th>Vulnerable</th>
                <th>Risk</th>
                <th>Risk Score</th>
                <th>Details</th>
              </tr>
              <!-- table data -->                      
                ${table}  
              <!-- table data -->              
            </table>          
	        </body>

          <script>  
            /*all functions based on templates from w3schools*/     

            function sortTable(n) {
              var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
              table = document.getElementById("table");
              switching = true;
              // Set the sorting direction to ascending:
              dir = "asc";
                          
              while (switching) {
                // Start by saying: no switching is done:
                switching = false;
                rows = table.rows;
                /* Loop through all table rows (except the
                first, which contains table headers): */
                for (i = 1; i < (rows.length - 1); i++) {
                  // Start by saying there should be no switching:
                  shouldSwitch = false;
                  /* Get the two elements you want to compare,
                  one from current row and one from the next: */
                  x = rows[i].getElementsByTagName("TD")[n];
                  y = rows[i + 1].getElementsByTagName("TD")[n];
                  /* Check if the two rows should switch place,
                  based on the direction, asc or desc: */
                  if (dir == "asc") {
                    if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
                      // If so, mark as a switch and break the loop:
                      shouldSwitch = true;
                      break;
                    }                    
                    if (Number(x.innerHTML) > Number(y.innerHTML)) {
                      //if so, mark as a switch and break the loop:
                      shouldSwitch = true;
                      break;
                    }
                  } else if (dir == "desc") {
                    if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
                      // If so, mark as a switch and break the loop:
                      shouldSwitch = true;
                      break;
                    }
                    if (Number(x.innerHTML) < Number(y.innerHTML)) {
                      //if so, mark as a switch and break the loop:
                      shouldSwitch = true;
                      break;
                    }
                  }
                }
                if (shouldSwitch) {
                  /* If a switch has been marked, make the switch
                  and mark that a switch has been done: */
                  rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
                  switching = true;
                  // Each time a switch is done, increase this count by 1:
                  switchcount ++;
                } else {
                  /* If no switching has been done AND the direction is "asc",
                  set the direction to "desc" and run the while loop again. */
                  if (switchcount == 0 && dir == "asc") {
                    dir = "desc";
                    switching = true;
                  }
                }
              }
            }

            function filterTable(n,id) {
              var input, filter, table, tr, td, i, txtValue;
              input = document.getElementById(id);
              filter = input.value.toUpperCase();
              table = document.getElementById("table");
              tr = table.getElementsByTagName("tr");
              for (i = 0; i < tr.length; i++) {
                td = tr[i].getElementsByTagName("td")[n];
                if (td) {
                  txtValue = td.textContent || td.innerText;
                  if (txtValue.toUpperCase().indexOf(filter) > -1) {
                    tr[i].style.display = "";
                  } else {
                    tr[i].style.display = "none";
                  }
                }       
              }
            }            
          </script>
          </html>
          `;
  }
}