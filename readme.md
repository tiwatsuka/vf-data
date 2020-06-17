# Results of analysis to identify fix revisions of vulnerabilities

## Description

This data set consists of the results of analysis done by our tool.
The tool automatically collect vulnerability information from NVD and do following analysis.

* Identifiyng repository
  The tool identifies source code repository of the product mentioned in description of the vulnerability.
* Identifying versions
  The tool identify release tags correspond to fix version and latest affected version of the vulnerability.
* Identifying fix revision
  The tool finds fix revisions of the vulnerability.

We manually classified them by the result of each analysis.

## Directories

The results of analysis are represented in one file per vulnerability.
They are located in the directories listed below.

* oss
  contains data for vulnerabilities of OSS
* oss/not_found
  contains data for vulnerabilities whose repositories were not found by the tool
* oss/correct_repository
  contains data for vulnerabilities whose correct repositories were identifined by the tool
* oss/correct_repository/correct_version
  contains data for vulnerabilities whose correct affected and fix versions were identified by the tool
* oss/correct_repository/correct_version/success
  contains data for vulnerabilities whose fix revisions were found by the tool
* oss/correct_repository/correct_version/failure
  contains data for vulnerabilities whose fix revisions were not found by the tool
* oss/correct_repository/wrong_version
  contains data for vulnerabilities whose correct affected and fix versions were not found by the tool
* oss/wrong_repository
  contains data for vulnerabilities whose repositories were wrongly identifined by the tool
* proprietary
  contains data for vulnerabilities of proprietary software
* proprietary/not_found
  contains data for vulnerabilities whose repositories were not found by the tool
* proprietary/wrong_repository
  contains data for vulnerabilities whose repositories were wrongly identifined by the tool

## Schema

Each data is represented as JSON.

```
{
    "cve":"CVE-2020-1699",    // CVE-ID
    "description":"A path traversal flaw was found in the Ceph dashboard implemented in upstream versions v14.2.5, v14.2.6, v15.0.0 of Ceph storage and has been fixed in versions 14.2.7 and 15.1.0. An unauthenticated attacker could use this flaw to cause information disclosure on the host machine running the Ceph dashboard.",    // Description of the vulnerability
    "fixes":[    // Fix revisions of the vulnerability which is manually verified 
        {
            "url":"https://github.com/ceph/ceph/commit/8392c2cb89a8419411843eaa6bc850ee9d7ef9be",    // The publicly accesible URL of the revision
            "hash":"8392c2cb89a8419411843eaa6bc850ee9d7ef9be",    // The identifier of the revision
            "message":"mgr/dashboard: fix improper URL checking"    // The comment for the revision
        }
    ],
    "analysis":[    // The result of analysis by the tool
        {
            "url":"https://github.com/ceph/ceph",    // Publicly accesible URL of the repository of the source code
            "affectedVersion":"v14.2.5",    // Tag name which corresponds to the latest affected version
            "fixVersion":"v14.2.6",    // Tag name which corresponds to the fix version
            "results":[    // The result for identify fix revisions
                {
                    "score":0.9927191,    // Cosine similarity to the description of the vulnerability
                    "message":"14.2.6",    // The comment for the revision
                    "hash":"f0aa067ac7a02ee46ea48aa26c6e298b5ea272e9"    // The identifier of the revision
                },
                {
                  ...
                },
                ...
            ]
        },
        {
            ...
        },
        ...
    ]
}
```
