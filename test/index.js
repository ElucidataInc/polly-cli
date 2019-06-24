#!/usr/bin/env node

var chalk = require('chalk');
var fs = require("fs");
var request = require("request");
var AWS = require('aws-sdk');
var AmazonCognitoIdentity = require('amazon-cognito-identity-js');
var public_token_header = '';
var jwt_decode = require('jwt-decode');
var DNS = require('dns')
var appNames = {"FirstView": "firstview", 
                "PollyPhi": "relative_lcms_elmaven", 
                "QuantFit": "calibration"};

module.exports.hello = function() {
    console.log(chalk.green.bold("Hello from the other side! :) "));
}

module.exports.check_internet_connection = function(){
    // assuming google server will always be up.
    DNS.resolve('www.google.com', function(err) {
        if (err) {
            console.error("No Internet Connection");
        } else {
            console.log("Connected");
        }
        });
}

function write_id_token(token_filename,idtoken) {
    var fso = require("fs");
    var buf = new Buffer(idtoken);
    fso.unlink(token_filename, (err) => {
        if (err) {
            var cred_file = fs.openSync(token_filename, 'wx');
            fso.writeSync(cred_file, buf);
        }
        else {
            console.log(chalk.green.bold("no error"));
            var cred_file = fs.openSync(token_filename, 'wx');
            fso.writeSync(cred_file, buf);
        }
    });

}


function has_id_token(token_filename) {
    var fso = require("fs");

    if(!fso.existsSync(token_filename)){
        return false;
    }
    return true;
}


function read_id_token(token_filename){
    var fso = require("fs");
    var saved_token = fso.readFileSync(token_filename);
    return saved_token;    
}

function refreshToken(token_filename,email){
    if (!email) {
        console.error(chalk.red.bold("Email is required to refresh the token"));
        return;
    } else {
        if (!(email.includes("@"))){
            console.error(chalk.red.bold("Please provide valid email.."));
            return;
        }
    }
    console.log(chalk.yellow.bold("Fetching user pool to refresh token..."));
    
    var options = {
        method: 'GET',
        url: 'https://api.testpolly.elucidata.io/userpool',
        json: true,
        headers:
        {
            'cache-control': 'no-cache'
        },
    };

    var cognito_client_id = "";
    var cognito_user_pool = "";
    var cognito_user_pool_region = "";

    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));

        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }

        console.log(chalk.yellow.bgBlack.bold("UserPool response: "));
        cognito_client_id = body.cognito_client_id;
        cognito_user_pool = body.cognito_user_pool;
        cognito_user_pool_region = body.cognito_user_pool_region;
        
        var poolData = {
            UserPoolId : cognito_user_pool,
            ClientId : cognito_client_id
        };
        var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
        var userData = {
            Username : email,
            Pool : userPool
        };
        
        var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
        var refresh_token = String(read_id_token(token_filename+"_refreshToken"))
        console.log("trying to refresh the token now..");
        var refresh_token_object = new AmazonCognitoIdentity.CognitoRefreshToken({ RefreshToken: refresh_token });
    
        cognitoUser.refreshSession(refresh_token_object, (err, session) => {
            if(err) {
                console.error("error while refreshing the token.."+err);
            } 
            else{
                write_id_token(token_filename, String(session.getIdToken().getJwtToken()));
                return;
            }
        });
        
    });
}

module.exports.authenticate = function(token_filename,email, password){
    if (has_id_token(token_filename) && has_id_token(token_filename+"_refreshToken")) {
        var public_token_header = read_id_token(token_filename);
        var decoded = jwt_decode(String(public_token_header));
        var token_expiry_date = decoded.exp.valueOf();
        var nowDate = new Date().getTime()/1000;
        // console.log(token_expiry_date,nowDate);
        if (token_expiry_date > nowDate) {
            console.log(chalk.green.bold("already logged in"));
            console.log("current user:", decoded.email.valueOf());
            return;
        }
        else{
            return refreshToken(token_filename,decoded.email.valueOf());
        }
    }
    if (!email) {
        console.error(chalk.red.bold("Email is required param."));
        return;
    } else {
        if (!(email.includes("@"))){
            console.error(chalk.red.bold("First param is email. Second param is password."));
            return;
            }
        }
    if (!password) {
        console.error(chalk.red.bold("Password is required param."));
        return;
    }
    console.log(chalk.yellow.bold("Fetching user pool..."));
    var options = {
        method: 'GET',
        url: 'https://api.testpolly.elucidata.io/userpool',
        json: true
    };

    var cognito_client_id = "";
    var cognito_user_pool = "";
    var cognito_user_pool_region = "";
    var CognitoUserPool = AmazonCognitoIdentity.CognitoUserPool;

    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));

        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }

        console.log(chalk.yellow.bgBlack.bold("UserPool response: "));
        cognito_client_id = body.cognito_client_id;
        cognito_user_pool = body.cognito_user_pool;
        cognito_user_pool_region = body.cognito_user_pool_region;
        
        var authenticationData = {
            Username : email,
            Password : password,
        };
        var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);
        // var authenticationDetails = new AWS.CognitoIdentityServiceProvider.AuthenticationDetails(authenticationData);
        var poolData = {
            UserPoolId : cognito_user_pool,
            ClientId : cognito_client_id
        };
        var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
        var userData = {
            Username : email,
            Pool : userPool
        };
        
        var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
        var loginidp = 'cognito-idp.ap-southeast-1.amazonaws.com/' + cognito_user_pool;
        cognitoUser.authenticateUser(authenticationDetails, {
            onSuccess: function (result) {
                write_id_token(token_filename,String(result.getIdToken().getJwtToken()));
                AWS.config.region = cognito_user_pool_region;
                write_id_token(token_filename+"_refreshToken",String(result.getRefreshToken().getToken()))
            
                AWS.config.credentials = new AWS.CognitoIdentityCredentials({
                    IdentityPoolId : cognito_client_id,
                    Logins : {
                        loginidp: result.getIdToken().getJwtToken()
                    }
                });
            },
            onFailure: function (result) {
                console.error(chalk.red.bgBlack.bold('Error while logging in. Please check your credentials on the web app.'));
            }
        });
    });
    return;
}

function isLicenseActive(jsonObj) {
    licenseObj = jsonObj.organization_details.licenses;
    licenseKeys = Object.keys(licenseObj);
    firstLicense = licenseObj[licenseKeys[0]];
    expireIn = firstLicense.remaining_days;
    return (expireIn >= 0);
}

module.exports.fetchAppLicense = function(token_filename) {
    if (has_id_token(token_filename)) {
        public_token_header = read_id_token(token_filename);
    }

    var options = {
        method: 'GET',
        url: 'https://api.testpolly.elucidata.io/me',
        headers:
            {
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'public-token': public_token_header
            },
        json: true
    }

    request(options, function(error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));

        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }

        jsonString = JSON.stringify(body);
        jsonObj = JSON.parse(jsonString);
        var activeLicense = 0;
        if (isLicenseActive(jsonObj)) {
            activeLicense = 1;
        }

        var myComponents = [];
        var myWorkflows = [];

        licenseObj = jsonObj.organization_details.licenses;
        licenseKeys = Object.keys(licenseObj);
        firstLicense = licenseObj[licenseKeys[0]];
        components = firstLicense.components;
        workflows = firstLicense.workflows;
        for(var component in components) {
            myComponents.push(components[component].component_id)
        }

        for (var workflow in workflows) {
            myWorkflows.push(workflows[workflow].workflow_id);
        }

        console.log("active components");
        console.log(myComponents);
        console.log("active workflows");
        console.log(myWorkflows);
        console.log("active license");
        console.log(activeLicense);

        return;
    });

}

module.exports.createWorkflowRequest = function (token_filename, 
                                                 project_id,
                                                 workflow_name,
                                                 workflow_id) {
    if (has_id_token(token_filename)) {
        public_token_header = read_id_token(token_filename);
    }
    var payload = {
        "workflow_details":{
            "workflow_name": workflow_name,
            "workflow_id": workflow_id
        },
        "name": "PollyPhi™ Relative LCMS El-MAVEN Untitled",
        "project_id": project_id
    };

    var options = {
        method: 'PUT',
        url: 'https://api.testpolly.elucidata.io/wf-request',
        headers:
            {
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'public-token': public_token_header
            },
        body:
            {
                payload: JSON.stringify(payload)
            },
        json: true
    };
    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        console.log(chalk.yellow.bgBlack.bold(`createWorkflowRequest Response: `));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        console.log(chalk.green.bold(JSON.stringify(body)));
        return body
    });
}

module.exports.createRunRequest = function (token_filename, component_id, project_id, extra_Info) {
    if (has_id_token(token_filename)) {
        public_token_header = read_id_token(token_filename);
    }

    var payload = {
        "component_details":{
            "component_name": "calibration_file_uploader_beta",
            "component_id": component_id
        },
        "project_id": project_id,
        "name": "Polly™ QuantFit Untitled"
    };
    if(extra_Info){
        payload["metadata"]={
            "additional_info":extra_Info,
            "import_workflow_id":"1-chanderprabh.jain@elucidata.io-1552461097169"
        }
    }
    console.log(payload)
    var options = {
        method: 'PUT',
        url: 'https://api.testpolly.elucidata.io/run',
        headers:
            {
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'public-token': public_token_header
            },
        body:
            {
                payload: JSON.stringify(payload)
            },
        json: true
    };

    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        console.log(chalk.yellow.bgBlack.bold(`createRunRequest Response: `));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        console.log(chalk.green.bold(JSON.stringify(body)));
        return body
    });
}

module.exports.getComponentName = function (appName) {
    console.log("appName: " + appNames[appName]);
}

module.exports.getComponentId = function (token_filename) {
    if (has_id_token(token_filename)) {
        public_token_header = read_id_token(token_filename);
    }
    var options = {
        method: 'GET',
        url: 'https://api.testpolly.elucidata.io/component',
        headers:
            {
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'public-token': public_token_header
            },
        qs:
            {
            },
        json: true
    };

    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        console.log(chalk.yellow.bgBlack.bold(`PostRun Response: `));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        console.log(chalk.green.bold(JSON.stringify(body)));
        return body
    });
}

module.exports.getWorkflowId = function (token_filename) {
    if (has_id_token(token_filename)) {
        public_token_header = read_id_token(token_filename);
    }
    var options = {
        method: 'GET',
        url: 'https://api.testpolly.elucidata.io/wf-fe-info',
        headers:
            {
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'public-token': public_token_header
            },
        qs:
            {
            },
        json: true
    };

    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        console.log(chalk.yellow.bgBlack.bold(`PostRun Response: `));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        console.log(chalk.green.bold(JSON.stringify(body)));
        return body
    });
}

module.exports.getEndpointForRuns = function (token_filename) {
    if (has_id_token(token_filename)) {
        public_token_header = read_id_token(token_filename);
    }
    var options = {
        method: 'GET',
        url: 'https://api.testpolly.elucidata.io/ui-endpoints',
        headers:
            {
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'public-token': public_token_header
            },
        qs:
            {
            },
        json: true
    };

    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        console.log(chalk.yellow.bgBlack.bold(`getEndpointForRun Response: `));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        console.log(chalk.green.bold(JSON.stringify(body)));
        return body
    });
}

module.exports.createProject = function (token_filename,name) {
    if (has_id_token(token_filename)) {
        public_token_header = read_id_token(token_filename);
    }
    var payload = {
        "name": name
    }
    var options = {
        method: 'POST',
        url: 'https://api.testpolly.elucidata.io/project',
        headers:
            {
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'public-token': public_token_header
            },
        body:
            {
                payload: JSON.stringify(payload)
            },
        json: true
    };
    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        console.log(chalk.yellow.bgBlack.bold(`createProject Response: `));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        console.log(chalk.green.bold(JSON.stringify(body)));
        return body
    });
}

module.exports.send_email = function (user_email, email_message, redirection_url, app_name) {
    if (!user_email) {
        console.error(chalk.red.bold("Email is required param."));
        return;
    } else {
        if (!(user_email.includes("@"))){
            console.error(chalk.red.bold("First param is email. Second param is email content. Third param is email_message. "));
            return;
            }
        }
    if (!redirection_url) {
        console.error(chalk.red.bold("email_content is required param."));
        return;
    }
    if (!email_message) {
        console.error(chalk.red.bold("email_message is required param."));
        return;
    }
    var options = {
        method: 'POST',
        url: 'https://7w9r94dq3h.execute-api.ap-south-1.amazonaws.com/cpj_beta/pyemail',
        headers:
            {
                'content-type': 'application/json'
            },
        body:
            {
                user_email: user_email,
                email_message: email_message,
                email_content: redirection_url,
                app_name: app_name
            },
        json: true
    };
    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        console.log(chalk.yellow.bgBlack.bold(`send email Response: `));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        console.log(chalk.green.bold(JSON.stringify(body)));
        return body
    });
}

module.exports.shareProject = function (token_filename,project_id,permission,usernames) {
    if (has_id_token(token_filename)) {
        public_token_header = read_id_token(token_filename);
    }
    var payload = {
        "project_sharing_list":
        [{"user_email":usernames,"project_id":project_id,"permission":permission}],
        "state":"share_project"
    }
    var options = {
        method: 'POST',
        url: 'https://api.testpolly.elucidata.io/sharing/share_project',
        headers:
            {
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'public-token': public_token_header
            },
        body:
            {
                payload: JSON.stringify(payload)
            },
        json: true
    };
    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        console.log(chalk.yellow.bgBlack.bold(`shareProject Response: `));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        console.log(chalk.green.bold(JSON.stringify(body)));
        return body
    });
}

module.exports.uploadCuratedPeakDataToCloud = function (signed_url, filePath) {
    var options = {
        method: 'PUT',
        url: signed_url,
        headers:
            {
                'x-amz-acl': 'bucket-owner-full-control',                
            },
        body: fs.readFileSync(filePath)
    };

    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        console.log(chalk.green.bold(response.statusCode));
    });
}

module.exports.getPeakUploadUrls = function (session_indentifier,file_name) {
    if (!session_indentifier) {
        console.error(chalk.red.bold("session_indentifier is required param."));
        return;
    }
    var options = {
        method: 'POST',
        url: 'https://zk0hjeh138.execute-api.ap-southeast-1.amazonaws.com/dev/eluploader',
        headers:
            {
                'content-type': 'application/json'
            },
        body:
            {
                format:"json",
                file_name: file_name,
                folder_name: session_indentifier
            },
        json: true
    };
    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        console.log(chalk.yellow.bgBlack.bold(`getPeakUploadUrls Response: `));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        console.log(chalk.green.bold(JSON.stringify(body)));
        return body
    });
}

   
module.exports.get_upload_Project_urls = function (token_filename,id) {
    if (has_id_token(token_filename)) {
        public_token_header = read_id_token(token_filename);
    }
    var options = {
        method: 'GET',
        url: 'https://api.testpolly.elucidata.io/project',
        headers:
            {
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'public-token': public_token_header                
            },
        qs:
            {
                id: id,
                state:"get_upload_urls"
            },
        json: true
    };

    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        console.log(chalk.yellow.bgBlack.bold(`PostRun Response: `));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        console.log(chalk.green.bold(JSON.stringify(body)));
        return body
    });
}


module.exports.get_Project_names = function (token_filename) {
    if (has_id_token(token_filename)) {
        public_token_header = read_id_token(token_filename);
    }
    var options = {
        method: 'GET',
        url: 'https://api.testpolly.elucidata.io/project',
        headers:
            {
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'public-token': public_token_header                
            },
        qs:
            {
            },
        json: true
    };

    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        console.log(chalk.yellow.bgBlack.bold(`PostRun Response: `));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        console.log(chalk.green.bold(JSON.stringify(body)));
        return body
    });
}

module.exports.get_organizational_databases = function (token_filename,organization) {
    if (has_id_token(token_filename)) {
        public_token_header = read_id_token(token_filename);
    }
    var options = {
        method: 'GET',
        url: 'https://api.testpolly.elucidata.io/project',
        headers:
            {
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'public-token': public_token_header                
            },
        qs:
            {
                // put state or something here, that will return all the names of compound DBs stored in 
                // organization folder of Elmaven-Polly-Integration bucket..
            },
        json: true
    };

    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        console.log(chalk.yellow.bgBlack.bold(`PostRun Response: `));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        console.log(chalk.green.bold(JSON.stringify(body)));
        return body
    });
}

module.exports.get_Project_files = function (token_filename,id) {
    if (has_id_token(token_filename)) {
        public_token_header = read_id_token(token_filename);
    }
    var options = {
        method: 'GET',
        url: 'https://api.testpolly.elucidata.io/project',
        headers:
            {
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'public-token': public_token_header                
            },
        qs:
            {
                id: id,
            },
        json: true
    };

    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        console.log(chalk.yellow.bgBlack.bold(`PostRun Response: `));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        console.log(chalk.green.bold(JSON.stringify(body)));
        return body
    });
}


module.exports.createPutRequest = function (token_filename,url, filePath) {
    if (has_id_token(token_filename)) {
        public_token_header = read_id_token(token_filename);
    }
    var options = {
        method: 'PUT',
        url: url,
        headers:
            {
                'cache-control': 'no-cache',
                'x-amz-acl': 'bucket-owner-full-control',
                'content-type': 'application/x-www-form-urlencoded',
                'public-token': public_token_header                
            },
        body: fs.readFileSync(filePath)
    };

    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        console.log(chalk.yellow.bgBlack.bold(`createPutRequest Response: `));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        console.log(chalk.green.bold(response.statusCode));
    });
}


module.exports.upload_project_data = function (url, filePath) {
    var options = {
        method: 'PUT',
        url: url,
        headers:
            {
                'x-amz-acl': 'bucket-owner-full-control',                
            },
        body: fs.readFileSync(filePath)
    };

    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        console.log(chalk.green.bold(response.statusCode));
    });
}

module.exports.download_project_data = function (url, filePath) {
    var options = {
        method: 'GET',
        url: url,
        headers:
            {
                'x-amz-acl': 'bucket-owner-full-control',                
            },
    };

    request(options, function (error, response, body) {
        if (error) throw new Error(chalk.bold.red(error));
        if (response.statusCode != 200) {
            console.error(JSON.stringify(response.body));
            return;
        }
        dataToWrite = response.body
        fs.writeFile(filePath, dataToWrite, 'utf8', function (err) {
            if (err) {
              console.error('Some error occured - file either not saved or corrupted file saved.');
            } else{
              console.log('It\'s saved!');
            }
        });
        console.log(chalk.green.bold(response.statusCode));
    });
}


require('make-runnable/custom')({
    printOutputFrame: false
})
