import multer from 'multer'

const storage = multer.memoryStorage()

//single upload
export const upload = multer({storage});

//multiple upload
export const multipuleUpload = multer({storage}).array("files",5)