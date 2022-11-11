import * as vscode from 'vscode';
import { runScan } from './scanner';
import { SidebarProvider } from './SidebarProvider';
import { WebViewPanel } from './WebViewPanel';

// Based on template that microsoft provides

// this method is called when your extension is activated
// your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {
	
	// initialize sidebar
	const sidebarProvider = new SidebarProvider(context.extensionUri);
	context.subscriptions.push(
	  vscode.window.registerWebviewViewProvider("cs-sidebar",sidebarProvider)
	);

	// start scan function
	context.subscriptions.push(
		vscode.commands.registerCommand('cs.startScan', () => {
			runScan();
			vscode.window.showInformationMessage("Dependency-Check Started, this could take a while.");          
		})
	);

	// show results webviewpanel function
	context.subscriptions.push(
		vscode.commands.registerCommand('cs.dcResults', () => {
			WebViewPanel.createOrShow(context.extensionUri);
		})
	);

	// refresh function
	context.subscriptions.push(
		vscode.commands.registerCommand('cs.refresh', async () => {
			WebViewPanel.kill();
			WebViewPanel.createOrShow(context.extensionUri);
			await vscode.commands.executeCommand("workbench.action.closeSidebar");
			await vscode.commands.executeCommand("workbench.view.extension.cs-sidebar-view");
		})
	);

	console.log('[Plugin started]');

}

// this method is called when your extension is deactivated
export function deactivate() {}
