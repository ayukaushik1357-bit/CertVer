import mongoose from "mongoose";

const { Schema, model, models } = mongoose;

const CandidateSchema = new Schema({
  candidateName: {
    type: String,
    required: true,
  },
  nicNumber: {
    type: String,
    required: true,
  },
  dateIssued: {
    type: String,
  },
  blockHash: {
    type: String,
    required: true,}
});

const CourseSchema = new Schema({
  courseId: {
    type: String,
    required: true,
  },
  courseName: {
    type: String,
  },
  candidates: [CandidateSchema],
});

const UserCourseRecordSchema = new Schema(
  {
    userId: {
      type: String,
      required: true,
      unique: true,
    },
    courses: [CourseSchema],
  }
);

export default models.UserCourseRecord ||
  model("UserCourseRecord", UserCourseRecordSchema);
