import { Router } from "express";
import { VideoRepository } from "../modules/videos/repositories/VideosRepository";
import {login} from "../middleware/login"

const videoRoutes = Router();
const videoRepository = new VideoRepository



videoRoutes.post('/create-video',login,(request,response)=>{
  videoRepository.create(request,response)
 })

 videoRoutes.get('/get-videos',login,(request,response)=>{
  videoRepository.getVideos(request,response)
 })

 videoRoutes.get('/search',(request,response)=>{
  videoRepository.serachVideos(request,response)
 })


 
 export {videoRoutes}