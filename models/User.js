const mongoose = require('mongoose'); 
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');

const userSchema = mongoose.Schema({ 
    name: {
        type: String,
        maxlength:50
    },
    email: {
        type: String,
        trim: true, 
        unique: 1 
    },
    password: {
        type:String,
        minlength:5
    },
    lastname: {
        type: String,
        maxlength: 50
    },
    role: {
        type: Number,
        default: 0 
    }, 
    image: String,
    token: { 
        type: String
    },
    tokenExp: { 
        type: Number
    }
})

userSchema.pre('save', function( next ){ 
    var user = this; 

    // password 변화될 때만 암호화되어 저장되도록 함
    if(user.isModified('password')){ 
         //비밀번호를 암호화 시킴
        bcrypt.genSalt(saltRounds, function(err, salt){
            if(err) return next(err);
    
            bcrypt.hash(user.password, salt, function(err, hash){ 
                if(err) return next(err);
                user.password = hash
                next();
            });
        });
    } else { //비밀번호가 아닌 다른 것을 바꿀 때
        next();
    }
})

userSchema.methods.comparePassword = function(plainPassword, cb){
    // plainPassword 1234567와 암호화된 비밀번호가 같은지 확인
    bcrypt.compare(plainPassword, this.password, function(err, isMatch){
        if(err) return cb(err);
        cb(null, isMatch); // isMatch = true
    })
}

userSchema.methods.generateToken = function(cb){

    var user = this;

    //jsonwebtoken을 이용해서 token을 생성
    var token = jwt.sign(user._id.toHexString(), 'secretToken') 
    //'secretToken' -> user._id가 나오도록 함
    // token을 가지고 누구인지를 알 수 있음

    user.token = token
    user.save(function(err, user) {
        if(err) return cb(err);
        cb(null, user)
    })
}

userSchema.statics.findByToken = function(token, cb){
    var user = this;

    //토큰을 decode
    //'secretToken'은 user._id+'secretToken'=token에서 중간에 있는 값
    jwt.verify(token, 'secretToken', function(err,decoded) { //decoded는 user._id
        //유저 아이디를 이용해서 유저를 찾은 다음에
        //클라이언트에서 가져온 token과 DB에 보관된 토큰이 일치하는지 확인
        user.findOne({ "_id":decoded, "token":token}, function(err, user){
            if(err) return cb(err)
            cb(null, user)
        })
    })
}

const User = mongoose.model('User',userSchema) 
module.exports = {User} 

