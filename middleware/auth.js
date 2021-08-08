const {User} = require("../models/User");


let auth = (req,res,next)=>{
    // 인증 처리를 하는 곳
    // 클라이언트 쿠키에서 토큰 가져오기(x_auth)
    let token = req.cookies.x_auth;

    //토큰을 복호화 한 후 유저 찾기
    // user 모델에서 메서드 만들기
    User.findByToken(token, (err,user)=>{
        if(err) throw err;
        if(!user) return res.json({isAuth:false, error:true}) //user가 없다면

        //user가 있다면
        req.token = token; 
        req.user = user;
        next(); 
    });

    // 유저 있으면 인증 ok
    // 유저 없으면 인증 no
}

module.exports = {auth};

