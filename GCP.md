## Google Cloud Platform Project

1. You will need to create a Google Cloud Platform Project as a first step. Make sure you are logged in to your Google Account (gmail, Google+, etc) and point your browser to https://console.cloud.google.com/projectselector/compute/instances. You should see a page asking you to create your first Project.
2. When creating a Project, you will see a pop-up dialog box. You can specify custom names but the Project ID is globally unique across all Google Cloud Platform customers.
3. It's OK to create a Project first, but you will need to set up billing before you can create any virtual machines with Compute Engine. Find the menu icon at the top left, then look for the Billing link in the navigation bar.
4. Next you will want to install the [Cloud SDK](https://cloud.google.com/sdk/) on your host machine and make sure you've successfully authenticated and set your default project as instructed.
   - After you install Cloud SDK, the next step is typically run the gcloud init command to perform initial setup tasks. You can also run [gcloud init](https://cloud.google.com/sdk/docs/initializing) at a later time to change your settings or create a new configuration.
5. You will also need to setup SSH keys that will allow you to access your Compute Engine instances. You can either manually generate the keys and paste the public key into the metadata server or you can use [gcloud compute ssh](https://cloud.google.com/compute/docs/instances/connecting-to-instance#gcetools) to access an existing Compute Engine instance and it will handle generating the keys and uploading them to the metadata server. For this demo, it is assumed you have opted to use gcloud compute ssh and your private key is located at $HOME/.ssh/google_compute_engine.
   ```
   gcloud compute ssh [INSTANCE_NAME]
   where [INSTANCE_NAME] is the name of the instance.
   ```
   
## Google Cloud Platform Compute Engine

1. Create a Google Cloud Platform Instance. Click “Create an Instance”.
2. Refer to “[Create a virtual machine instance](https://cloud.google.com/compute/docs/quickstart-linux#create_a_virtual_machine_instance)” for details on spinning up a compute engine and selecting a zone.
3. For this example we are going to go with the following machine instance resources:
      * Machine type: small (1 shared vCPU)
        * 1.7 GB memory, g1-small
      * Boot disk: Ubuntu 14.04 LTS
      * Boot disk type: Standard Persistent Disk | Size (GB): 40
      * Networking: Set to Static IP
      * Select “Create” to launch instance

   Once you have the instance up and running move over to steps in READ.ME under <b>Software Dependencies</b>.
