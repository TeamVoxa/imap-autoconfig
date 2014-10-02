var autoconfig = require("./autoconfig"),
    dnscheck = require("./dnscheck"),
    guess = require("./guess"),
    inbox = require("inbox");

module.exports.detectIMAPSettings = detectIMAPSettings;

function detectIMAPConnectionSettings(address, secret, callback){
    var password;
    var oauthToken;
    if(!callback && typeof secret == "function"){
        callback = password;
        secret = undefined;
        oauthToken = undefined;
        password = undefined;
    }   

    var funcs = [
            autoconfig.detectIMAPConnectionSettings.bind(autoconfig),
            dnscheck.detectIMAPConnectionSettings.bind(dnscheck),
            guess.detectIMAPConnectionSettings.bind(guess)
        ],
        ready = false,
        waitingFor = funcs.length;

    for(var i=0, len = funcs.length; i<len; i++){
        funcs[i](address, secret, function(err, data){
            waitingFor--;

            if(ready){
                return;
            }
            
            if(data){
                ready = true;
                return callback(null, data);
            }

            if(waitingFor === 0){
                return callback(null, null);
            }
        });
    }
}

function checkLoginData(port, host, options, callback){
    var client = inbox.createConnection(port, host, options),
        done = false;
    client.connect();
    client.on("connect", function(){
        if(done){return;}
        done = true;
        client.close();
        callback(null, true);
    });

    client.on("error", function(err){
        if(done){return;}
        done = true;
        client.close();
        callback(err);
    });
}

function detectIMAPUserSettings(address, secret, settings, callback){
    var inboxSettings;
    
    if(secret.oauthToken){
        
        inboxSettings = {
            secureConnection: !!settings.secure,
            auth: {
                XOAuthToken: secret.oauthToken,
                user: address
            }
        };
    }

    if(secret.password){
        inboxSettings = {
            secureConnection: !!settings.secure,
            auth: {
                pass: secret.password,
                user: address
            }
        };
    }

    

    checkLoginData(settings.port, settings.host, inboxSettings, function(err, success){
        if(err){
            inboxSettings.auth.user = address.split("@")[0];
            checkLoginData(settings.port, settings.host, inboxSettings, function(err, success){
                if(err){
                    return callback(err);
                }
                callback(null, "%USER%");
            });
        }else{
            callback(null, "%EMAIL%");
        }
    });

}


function detectIMAPSettings(address, secret, callback){
    if(!callback && typeof secret == "function"){
        callback = secret;
        secret = undefined;
    }

    detectIMAPConnectionSettings(address, secret, function(err, settings){
        if(err){
            return callback(err);
        }

        if(settings && secret){
            detectIMAPUserSettings(address, secret, settings, function(err, user){
                if(err){
                    settings.user = false;
                    settings.error = err.message;
                }else{
                    settings.user = user;
                }

                callback(null, settings);
            });
        }else{
            callback(null, settings);
        }
    });
}