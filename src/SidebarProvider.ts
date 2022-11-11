import * as vscode from "vscode";
import { getNonce } from "./functions";
import { runScan } from "./scanner";

// Based on template that microsoft provides

export class SidebarProvider implements vscode.WebviewViewProvider {
  _view?: vscode.WebviewView;
  _doc?: vscode.TextDocument;

  constructor(private readonly _extensionUri: vscode.Uri) {}

  public resolveWebviewView(webviewView: vscode.WebviewView) {
    this._view = webviewView;

    webviewView.webview.options = {
      // Allow scripts in the webview
      enableScripts: true,
      localResourceRoots: [this._extensionUri],
    };

    webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

    webviewView.webview.onDidReceiveMessage(async (data) => {
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
        case "startScan": {
          if (!data.value) {
            return;
          }
          await runScan();
          vscode.window.showInformationMessage(data.value);          
          break;
        }
        case "showResults": {
          if (!data.value) {
            return;
          }
          vscode.commands.executeCommand('cs.dcResults');
          break;
        }        
      }
    });
  }

  public revive(panel: vscode.WebviewView) {
    this._view = panel;
  }

  private _getHtmlForWebview(webview: vscode.Webview) {
    const scriptUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media/compiled", "sidebar.js")
    );

    const styleResetUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "reset.css")
    );
    const styleVSCodeUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "vscode.css")
      );
    const styleMainUri = webview.asWebviewUri(
      vscode.Uri.joinPath(this._extensionUri, "media", "custom.css")
    );

    // Use a nonce to only allow a specific script to be run.
    const nonce = getNonce();

    return `
          <!DOCTYPE html>
	        <html lang="en">
	        <head>
	          <meta charset="UTF-8">
            <meta http-equiv="Content-Security-Policy" content="img-src https: data:; style-src 'unsafe-inline' ${webview.cspSource}; script-src 'nonce-${nonce}';">
		        <meta name="viewport" content="width=device-width, initial-scale=1.0">
		        <link href="${styleResetUri}" rel="stylesheet">
		        <link href="${styleVSCodeUri}" rel="stylesheet">
            <link href="${styleMainUri}" rel="stylesheet">
	        </head>
          <script nonce="${nonce}">const tsvscode = acquireVsCodeApi();</script>
          <body class="background">
            <!-- Svelte components will be inserted in body section -->
	        </body>
          <script src="${scriptUri}" nonce="${nonce}"></script>
          </html>
          `;
  }
}