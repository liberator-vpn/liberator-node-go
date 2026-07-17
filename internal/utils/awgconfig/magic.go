package awgconfig

import (
	"fmt"
	"math/rand"
)

// GenerateMagicHeaders генерирует 4 НЕПЕРЕСЕКАЮЩИХСЯ диапазона для H1-H4.
// Разбивает пространство uint32 на 4 безопасные зоны, далекие от стандартных
// заголовков WireGuard (1, 2, 3, 4) и друг от друга.
func GenerateMagicHeaders() (H1, H2, H3, H4 string) {
	// Зоны (начало и конец корзины). Они не пересекаются.
	H1 = generateSafeRange(1000000000, 1999999999)
	H2 = generateSafeRange(2000000000, 2999999999)
	H3 = generateSafeRange(3000000000, 3999999999)
	H4 = generateSafeRange(4000000000, 4294967295) // До максимального uint32
	return
}

// generateSafeRange создает строку "x-y" внутри заданной корзины
func generateSafeRange(bucketMin, bucketMax uint32) string {
	// Ширина нашего диапазона (чем больше, тем сложнее DPI угадать, 100к - отлично)
	rangeWidth := uint32(100000)

	// Проверяем, что корзина достаточно велика
	diff := bucketMax - bucketMin
	if diff <= rangeWidth {
		// Если корзина вдруг слишком маленькая, используем её целиком
		return fmt.Sprintf("%d-%d", bucketMin, bucketMax)
	}

	// Вычисляем максимальную стартовую точку, чтобы мы не вышли за корзину
	maxStart := diff - rangeWidth

	// Генерируем случайную стартовую точку внутри корзины
	start := bucketMin + rand.Uint32()%(maxStart+1)
	end := start + rangeWidth

	return fmt.Sprintf("%d-%d", start, end)
}
