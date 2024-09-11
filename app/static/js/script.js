document.addEventListener("DOMContentLoaded", function () {

    const customPortRadio = document.getElementById("custom_ports");
    const commonPortRadio = document.getElementById("common_ports");
    const portInput = document.getElementById("custom-port-input");

    const summaryDiv = document.getElementById('summary-boxes');
    const rawOutput = document.getElementById('raw-output');
    const parametersOutput = document.getElementById('parameters-output');
    

    // Show or hide custom port input based on selected option
    if (customPortRadio && commonPortRadio && portInput) {
        customPortRadio.addEventListener("change", function () {
            portInput.style.display = "block";
        });

        commonPortRadio.addEventListener("change", function () {
            portInput.style.display = "none";
        });
    }

    // Initialize socket connection
    // # for local devlopment
    // const socket = io.connect('http://' + document.domain + ':' + location.port);
    // for production
    const socket = io('https://letscan.io', { transports: ['websocket', 'polling'] });
    socket.on('connect', function() {
        console.log('Socket connected');
    });

    // socket.on('scan_progress', function (data) {
    //     console.log("Received scan_progress event:", data);
    //     if (scanOutput) {
    //         scanOutput.innerHTML += `<p>Host: ${data.host} (${data.hostname})</p>`;
    //         scanOutput.innerHTML += `<p>Status: ${data.status}</p>`;
    //         data.ports.forEach(port => {
    //             scanOutput.innerHTML += `<p>Port: ${port.port}, Protocol: ${port.protocol}, State: ${port.state}</p>`;
    //         });
    //     }
    // });

    // socket.on('scan_complete', function (data) {
    //     console.log("Received scan_complete event:", data);
    //     hideSpinner();  // Ensure the spinner is hidden
    //     scanOutput.innerHTML += `<h2>${data.message}</h2>`;
    //     updateScanSummary('Done', data.summary);
    // });
    
    // socket.on('scan_error', function (data) {
    //     console.log("Received scan_error event:", data);
    //     hideSpinner();  // Ensure the spinner is hidden
    //     scanOutput.innerHTML += `<h2>Error: ${data.error}</h2>`;
    //     updateScanSummary('Failed', {});
    // });

    socket.on('scan_progress', function (data) {
        console.log("Received scan_progress event:", data);
        rawOutput.innerHTML = `
                <tr>
                    <td>Host: </td>
                    <td>${data.host}</td>
                </tr>
                <tr>
                    <td>Status</td>
                    <td>${data.status}</td>
                </tr>
            `;
        ports_row = document.createElement('tr');
        ports_row.innerHTML = `<td> Ports </d>`
        ports_td_column = document.createElement('td')
        data.ports.forEach(port => {
            ports_td_column.innerText += `Port: ${port.port}, Protocol: ${port.protocol}, State: ${port.state}\n`;
        });
        ports_row.appendChild(ports_td_column)
        rawOutput.appendChild(ports_row,)
    });

    function updateScanSummary(status, summaryData) {
        if (summaryDiv) {
            const host = summaryData?.host || 'N/A';
            const ports = summaryData?.ports?.join(', ') || 'N/A';
            const hosts = summaryData?.hosts?.join(', ') || 'N/A';
            const startTime = summaryData?.startTime || 'N/A';
            const finishTime = summaryData?.finishTime || 'N/A';
            const duration = summaryData?.duration || 'N/A';

            summaryDiv.innerHTML = `
                <div class="summary-box">
                    <p><strong>IP:</strong> ${host}</p>
                    <p><strong>Status:</strong> ${status}</p>
                    <p><strong>Open Ports:</strong> ${ports}</p>
                    <p><strong>Hosts:</strong> ${hosts}</p>
                    <p><strong>Start Time:</strong> ${startTime}</p>
                    <p><strong>Finish Time:</strong> ${finishTime}</p>
                    <p><strong>Scan Duration:</strong> ${duration} seconds</p>
                </div>
            `;
        }
    }


    // form submission logic
    const form = document.getElementById("port-scan-form");
    if (form) {
        form.addEventListener("submit", function (e) {
            e.preventDefault();
            showSpinner();

            const target = document.getElementById("target").value;
            const scanType = document.querySelector('input[name="scan_type"]:checked').value;
            const portOption = document.querySelector('input[name="port_option"]:checked').value;
            const osDetection = document.getElementById("os_detection").checked ? 'on' : 'off';
            
            let ports = portOption === "common" ? "common" : document.getElementById("ports_to_scan").value;

            parametersOutput.innerHTML = `
                <tr>
                    <td><b>Target:</b> </td>
                    <td>${target}</td>
                </tr>
                <tr>
                    <td><b>Scan Type:</b> </td>
                    <td>${scanType}</td>
                </tr>
                <tr>
                    <td><b>Ports:</b> </td>
                    <td>${ports}</td>
                </tr>
                <tr>
                    <td><b>OS detection:</b> </td>
                    <td>${osDetection}</td>
                </tr>
            `;
            // console.log('os-detection output is below:')
            // console.log(osDetection)
            socket.emit('start_scan', {
                target: target,
                scan_type: scanType,
                ports: ports,
                os_detection: osDetection
            });
        });
    }
});
