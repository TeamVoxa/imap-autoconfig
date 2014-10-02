var defaultConfig = require("./config.json"),
    detect = require("./lib/detect"),
    redis = require("redis"),
    crypto = require("crypto");

module.exports.createIMAPSettingsDetector = createIMAPSettingsDetector;

function createIMAPSettingsDetector(config){
    config = config || defaultConfig;
    config.redis = config.redis || defaultConfig.redis;

    if(typeof config.cacheExpire == "undefined"){
        config.cacheExpire = defaultConfig.cacheExpire;
    }

    return new IMAPSettingsDetector(config);
}

function IMAPSettingsDetector(config){
    this.config = config;
    this.redisClient = redis.createClient(config.redis.port, config.redis.host);
}

IMAPSettingsDetector.prototype.detect = function(address, secret, cached, callback){
    var args = Array.prototype.slice.call(arguments);

    callback = args.pop();

    address = args[0];
    secret = args[1] || "";
    cached = args[2];

    var cacheKey = "cache:autoconfig:"+sha1(address.split("@")[1] || "localhost");

    if(cached){
        this.redisClient.multi().
            select(this.config.redis.db).
            hgetall(cacheKey).
            ttl(cacheKey).
            exec((function(err, replies){
                if(err){
                    return callback(err);
                }
                if(replies && replies[1]){
                    if(replies[2]){
                        replies[1].expires = new Date(Date.now() + replies[2]*1000);
                    }
                    
                    //console.log("Cache hit (expires " +replies[1].expires+ ")");
                    return callback(null, replies[1]);
                }
                //console.log("Cache miss");
                this._checkSettings(address, secret, cacheKey, callback);
            }).bind(this));
    }else{
        this._checkSettings(address, secret, cacheKey, callback);
    }
};

IMAPSettingsDetector.prototype._checkSettings = function(address, secret, cacheKey, callback){
    detect.detectIMAPSettings(address, secret, (function(err, settings){
        
        if(err){
            return callback(err);
        }

        if(!settings){
            return callback(null, null);
        }

        // overwrite cache only with a valid user information
        if(settings.user){
            this.redisClient.multi().
                select(this.config.redis.db).
                hmset(cacheKey, settings).
                expire(cacheKey, this.config.cacheExpire || 0).
                exec((function(err){
                    callback(null, settings);
                }).bind(this));    
        }else{
            callback(null, settings);
        }

    }).bind(this));
};


function sha1(str){
    var hash = crypto.createHash("sha1");
    hash.update(str);
    return hash.digest("hex");
}
