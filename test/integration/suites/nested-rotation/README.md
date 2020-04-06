# Nested rotation Suite

## Description

This suite sets a very low TTLs and ensures that workload SVIDs are valid
across many SVID and SPIRE server CA rotation periods using nested servers.
Integration test is configured to work with 3 layers for server/agents:

                         root-server
                              |  
                         root-agent
                        /           \
         intermediateA-server   intermediateA-server      
                |                       |
         intermediateA-agent    intermediateA-agent    
                |                       |
           leafA-server            leafA-server  
                |                       |
           leafA-agent             leafA-agent             

Test steps:

- fetch x509-SVID from `intermediateA-agent` and validate them on `intermediateB-agent` using `spire-agent api validate x509` 
- fetch x509-SVID from `leafA-agent` and validate them on `leafB-agent` using `spire-agent api validate x509` 
- fetch jwt-SVID from `intermediateA-agent` and validate them on `intermediateB-agent` using `spire-agent api validate jwt` 
- fetch jwt-SVID from `leafA-agent` and validate them on `leafB-agent` using `spire-agent api validate jwt` 
