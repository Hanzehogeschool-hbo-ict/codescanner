import * as vscode from "vscode";

export function getNonce() {
	let text = '';
	const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	for (let i = 0; i < 32; i++) {
		text += possible.charAt(Math.floor(Math.random() * possible.length));
	}
	return text;
}

export function workspaceFolder(){
	var wf = undefined;
	if(vscode.workspace.workspaceFolders !== undefined) {
	  wf = (vscode.workspace.workspaceFolders[0].uri.path).substring(1); // substring removes first "/" of the wf path           
	} else {
	  wf = "None";
	}
	return(wf);
  }

export function round(value:number, precision:number) {
    var multiplier = Math.pow(10, precision || 0);
    return Math.round(value * multiplier) / multiplier;
}
  