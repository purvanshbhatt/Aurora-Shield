import { Router, type IRouter } from "express";
import healthRouter from "./health";
import analyzeRouter from "./analyze-new";

const router: IRouter = Router();

router.use(healthRouter);
router.use("/analyze", analyzeRouter);

export default router;
