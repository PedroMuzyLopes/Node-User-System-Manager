import mongoose from "mongoose";

const User = mongoose.model("User", {
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    required: true
  },
  sector: {
    type: String,
    required: true
  },
  systems: {
    type: Array
  }
});

export default User;

