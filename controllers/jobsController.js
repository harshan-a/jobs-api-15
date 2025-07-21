const {StatusCodes} = require("http-status-codes");

const Job = require("../models/jobModel");
const {NotFoundError} = require("../errors");


const createJob = async (req, res) => {
  req.body.createdBy = req.user.userId;

  const job = await Job.create(req.body);
  res.status(StatusCodes.CREATED).json({data: job});
}

const getAllJobs = async (req, res) => {
  const {userId} = req.user;
  const jobs = await Job.find({createdBy: userId});

  res
    .status(StatusCodes.OK)
    .json({success: true, data: jobs, count: jobs.length});
}

const getJob = async (req, res) => {
  // const {id:jobId} = req.params;
  // const {userId} = req.user;
  const {
    user: {userId, userName}, 
    params: {id:jobId}
  } = req;

  const job = await Job.findOne({_id: jobId, createdBy: userId});
  if(!job) 
    throw new NotFoundError("No job found wid id : " + jobId);

  res
    .status(StatusCodes.OK)
    .json({success: true, data: job});
}

const updateJob = async (req, res) => {
  // const {id:jobId} = req.params;
  // const {userId} = req.user;
  const {user: {userId}, params: {id:jobId}} = req;

  const job = await Job.findOneAndUpdate(
    {_id: jobId, createdBy: userId}, 
    {...req.body},
    {
      runValidators: true,
      new: true,
    }
  )
  if(!job) 
    throw new NotFoundError("No job found wid id: " + jobId);

  res
    .status(StatusCodes.OK)
    .json({success: true, data: job});
  
}

const deleteJob = async (req, res) => {
  // const {id:jobId} = req.params;
  // const {userId} = req.user;
  const {
    user: {userId}, 
    params: {id:jobId}
  } = req;

  const job = await Job.findOneAndDelete(
    {_id: jobId, createdBy: userId},
  )
  if(!job) 
    throw new NotFoundError("No job found wid id: " + jobId);

  res
    .status(StatusCodes.OK)
    .json({success: true, data: job});
}

module.exports = {
  getAllJobs,
  getJob,
  createJob,
  deleteJob,
  updateJob,
};