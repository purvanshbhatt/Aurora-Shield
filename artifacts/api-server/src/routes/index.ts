import { Router, type IRouter } from "express";
import healthRouter from "./health";
import analyzeRouter from "./analyze";

const router: IRouter = Router();

router.use(healthRouter);
router.use("/analyze", analyzeRouter);

export default router;
