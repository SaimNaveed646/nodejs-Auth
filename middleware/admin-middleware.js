const isAdminUser = (req, res, next) => {
    if (req.userInfo.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Access denied! Admin rights required.",
      });
    }
  
    next();
  };


  const changePassword = async (req, res) => {
    try {
      const userId = req.userInfo.userId;
  
      //extract old and new password;
      const { oldPassword, newPassword } = req.body;
  
      //find the current logged in user
      const user = await User.findById(userId);
  
      if (!user) {
        return res.status(400).json({
          success: false,
          message: "User not found",
        });
      }
  
      //check if the old password is correct
      const isPasswordMatch = await bcrypt.compare(oldPassword, user.password);
  
      if (!isPasswordMatch) {
        return res.status(400).json({
          success: false,
          message: "Old password is not correct! Please try again.",
        });
      }
  
      //hash the new password here
      const salt = await bcrypt.genSalt(10);
      const newHashedPassword = await bcrypt.hash(newPassword, salt);
  
      //update user password
      user.password = newHashedPassword;
      await user.save();
  
      res.status(200).json({
        success: true,
        message: "Password changed successfully",
      });
    } catch (e) {
      console.log(e);
      res.status(500).json({
        success: false,
        message: "Some error occured! Please try again",
      });
    }
  };
  
  
  module.exports = isAdminUser;