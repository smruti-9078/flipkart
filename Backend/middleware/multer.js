import multer from 'multer'

const storage = multer.memoryStorage()

const upload = multer({
  storage,
  limits: { fileSize: 1024 * 1024 * 5 },
})

export const uploadSingle = upload.single('productImg')
export const multipleUpload = upload.array('productImg', 5)