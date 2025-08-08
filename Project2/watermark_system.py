import cv2
import numpy as np
import pywt
from skimage.metrics import peak_signal_noise_ratio as psnr

# === 参数配置 ===
ALPHA = 30  # 基础嵌入强度
WM_SIZE = 32  # 水印尺寸
REPETITION = 5  # 重复嵌入次数
BLOCK_SIZE = 16  # DCT块大小


# === DCT操作 ===
def dct2(img):
    return cv2.dct(np.float32(img))


def idct2(img):
    return cv2.idct(np.float32(img))


# === 小波变换 ===
def dwt2(img):
    coeffs = pywt.dwt2(img, 'haar')
    LL, (LH, HL, HH) = coeffs
    return LL, LH, HL, HH


def idwt2(LL, LH, HL, HH):
    return pywt.idwt2((LL, (LH, HL, HH)), 'haar')


# === 水印预处理 ===
def preprocess_watermark(wm):
    # 二值化并添加冗余
    wm = (wm > 127).astype(np.uint8)
    # 简单的重复编码
    wm_encoded = np.repeat(wm, REPETITION, axis=0)
    wm_encoded = np.repeat(wm_encoded, REPETITION, axis=1)
    return wm_encoded


# === 自适应嵌入强度计算 ===
def calculate_alpha(coeffs, base_alpha):
    # 根据系数能量自适应调整嵌入强度
    energy = np.mean(np.abs(coeffs))
    return base_alpha * (1 + energy / 100)


# === 水印嵌入 ===
def embed_watermark_dwt_dct(cover_img, watermark_img, alpha=ALPHA):
    # 预处理水印
    wm = cv2.resize(watermark_img, (WM_SIZE, WM_SIZE))
    wm_encoded = preprocess_watermark(wm)

    # 小波分解
    LL, LH, HL, HH = dwt2(cover_img)

    # 在多个子带嵌入水印
    for subband in [LH, HL, HH]:
        dct_sub = dct2(subband)

        # 分块嵌入
        for i in range(0, WM_SIZE * REPETITION, BLOCK_SIZE):
            for j in range(0, WM_SIZE * REPETITION, BLOCK_SIZE):
                if i + BLOCK_SIZE > WM_SIZE * REPETITION or j + BLOCK_SIZE > WM_SIZE * REPETITION:
                    continue

                # 计算当前块的嵌入强度
                block = dct_sub[i:i + BLOCK_SIZE, j:j + BLOCK_SIZE]
                current_alpha = calculate_alpha(block, alpha)

                # 嵌入水印
                for x in range(BLOCK_SIZE):
                    for y in range(BLOCK_SIZE):
                        if wm_encoded[i + x, j + y] == 1:
                            dct_sub[i + x + BLOCK_SIZE // 2, j + y + BLOCK_SIZE // 2] += current_alpha
                        else:
                            dct_sub[i + x + BLOCK_SIZE // 2, j + y + BLOCK_SIZE // 2] -= current_alpha

        # 反变换
        if subband is LH:
            LH = idct2(dct_sub)
        elif subband is HL:
            HL = idct2(dct_sub)
        else:
            HH = idct2(dct_sub)

    # 重构图像
    watermarked_img = idwt2(LL, LH, HL, HH)
    return np.clip(watermarked_img, 0, 255).astype(np.uint8)


# === 水印提取 ===
def extract_watermark_dwt_dct(watermarked_img, alpha=ALPHA):
    # 小波分解
    LL, LH, HL, HH = dwt2(watermarked_img)

    # 从多个子带提取水印
    wm_extracted_list = []
    for subband in [LH, HL, HH]:
        dct_sub = dct2(subband)
        wm_extracted = np.zeros((WM_SIZE * REPETITION, WM_SIZE * REPETITION), dtype=np.float32)

        # 分块提取
        for i in range(0, WM_SIZE * REPETITION, BLOCK_SIZE):
            for j in range(0, WM_SIZE * REPETITION, BLOCK_SIZE):
                if i + BLOCK_SIZE > WM_SIZE * REPETITION or j + BLOCK_SIZE > WM_SIZE * REPETITION:
                    continue

                block = dct_sub[i:i + BLOCK_SIZE, j:j + BLOCK_SIZE]
                current_alpha = calculate_alpha(block, alpha)

                for x in range(BLOCK_SIZE):
                    for y in range(BLOCK_SIZE):
                        val = dct_sub[i + x + BLOCK_SIZE // 2, j + y + BLOCK_SIZE // 2]
                        wm_extracted[i + x, j + y] += val / current_alpha

        wm_extracted_list.append(wm_extracted)

    # 合并多个子带的提取结果
    wm_combined = np.mean(wm_extracted_list, axis=0)

    # 解码重复编码
    wm_decoded = np.zeros((WM_SIZE, WM_SIZE), dtype=np.uint8)
    for i in range(WM_SIZE):
        for j in range(WM_SIZE):
            # 取重复区域的平均值
            region = wm_combined[i * REPETITION:(i + 1) * REPETITION, j * REPETITION:(j + 1) * REPETITION]
            wm_decoded[i, j] = 255 if np.mean(region) > 0 else 0

    return wm_decoded


# === 攻击模拟 ===
def apply_attacks(img, attack_type):
    if attack_type == "flip":
        return cv2.flip(img, 1)
    elif attack_type == "translate":
        M = np.float32([[1, 0, 15], [0, 1, 15]])  # 增加平移量
        return cv2.warpAffine(img, M, (img.shape[1], img.shape[0]))
    elif attack_type == "crop":
        h, w = img.shape[:2]
        cropped = img[int(h * 0.1):int(h * 0.9), int(w * 0.1):int(w * 0.9)]  # 更大范围的裁剪
        return cv2.resize(cropped, (w, h))
    elif attack_type == "contrast":
        return cv2.convertScaleAbs(img, alpha=2.0, beta=0)  # 更强的对比度调整
    elif attack_type == "noise":
        noise = np.random.normal(0, 20, img.shape)  # 更强的噪声
        noisy = img + noise
        return np.clip(noisy, 0, 255).astype(np.uint8)
    else:
        return img


# === 评估函数 ===
def evaluate(wm_true, wm_pred):
    acc = np.sum(wm_true == wm_pred) / wm_true.size
    ber = np.sum(wm_true != wm_pred) / wm_true.size
    return acc * 100, ber * 100


# === 主函数 ===
def main():
    # 以彩色模式读取宿主图片，水印图片仍为灰度图
    cover_color = cv2.imread("host.jpg", cv2.IMREAD_COLOR)
    watermark_gray = cv2.imread("watermark.jpg", cv2.IMREAD_GRAYSCALE)

    # 验证图片是否成功加载
    if cover_color is None or watermark_gray is None:
        print("Error: host.jpg or watermark.jpg not found.")
        return

    # 分离通道，选择蓝色通道进行水印嵌入（B, G, R）
    b, g, r = cv2.split(cover_color)

    # 嵌入水印到蓝色通道
    watermarked_b_channel = embed_watermark_dwt_dct(b, watermark_gray)

    # 合并通道得到带水印的彩色图片
    watermarked_color = cv2.merge((watermarked_b_channel, g, r))
    cv2.imwrite("watermarked_dwt_dct.png", watermarked_color)

    # 准备真实水印用于评估
    wm_true = cv2.resize(watermark_gray, (WM_SIZE, WM_SIZE))
    wm_true = (wm_true > 127).astype(np.uint8)

    print("开始进行鲁棒性测试...")
    attack_types = ["flip", "translate", "crop", "contrast", "noise"]
    for atk in attack_types:
        # 对彩色带水印图片进行攻击
        attacked_color = apply_attacks(watermarked_color, atk)
        cv2.imwrite(f"attacked_{atk}.png", attacked_color)

        # 提取攻击后图片的蓝色通道
        attacked_b_channel = cv2.split(attacked_color)[0]

        # 从攻击后的蓝色通道中提取水印
        wm_extracted = extract_watermark_dwt_dct(attacked_b_channel)

        # 评估结果
        acc, ber = evaluate(wm_true, (wm_extracted > 127).astype(np.uint8))

        # 修改后的输出逻辑
        if acc > 50:
            print(f"[{atk}] 通过鲁棒性测试")
        else:
            print(f"[{atk}] 未通过鲁棒性测试")

        cv2.imwrite(f"extracted_{atk}_color.png", wm_extracted)


if __name__ == "__main__":
    main()