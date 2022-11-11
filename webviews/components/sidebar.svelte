<script lang="ts">
</script>

<h2 class="whitespace-top">Dependency Check</h2>

<p>The Dependency Check will launch a dependency check tool. This process can take a while, please be patient.</p>
<button 
    on:click={() => {
        tsvscode.postMessage({type: "startScan",value: "Dependency check has been started, Please wait."})
    }}>Start Scan</button>

<p>After the scan has finished click the "Show Results" button to see the results of the scan.</p>
<button 
on:click={() => {
    tsvscode.postMessage({type: "showResults",value: "hallo"})
}}>Show Results</button>  

<!-- <p></p>
<button 
on:click={() => {
    tsvscode.postMessage({type: "onInfo",value: "Results are being exported."})
}}>Export results</button> -->
