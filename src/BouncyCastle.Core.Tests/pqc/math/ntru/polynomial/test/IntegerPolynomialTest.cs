namespace org.bouncycastle.pqc.math.ntru.polynomial.test
{

	using TestCase = junit.framework.TestCase;
	using NTRUSigningKeyGenerationParameters = org.bouncycastle.pqc.crypto.ntru.NTRUSigningKeyGenerationParameters;
	using Arrays = org.bouncycastle.util.Arrays;


	public class IntegerPolynomialTest : TestCase
	{
		public virtual void testMult()
		{
			// multiplication modulo q
			IntegerPolynomial a = new IntegerPolynomial(new int[]{-1, 1, 1, 0, -1, 0, 1, 0, 0, 1, -1});
			IntegerPolynomial b = new IntegerPolynomial(new int[]{14, 11, 26, 24, 14, 16, 30, 7, 25, 6, 19});
			IntegerPolynomial c = a.mult(b, 32);
			assertEqualsMod(new int[]{3, -7, -10, -11, 10, 7, 6, 7, 5, -3, -7}, c.coeffs, 32);

			a = new IntegerPolynomial(new int[]{15, 27, 18, 16, 12, 13, 16, 2, 28, 22, 26});
			b = new IntegerPolynomial(new int[]{-1, 0, 1, 1, 0, 1, 0, 0, -1, 0, -1});
			c = a.mult(b, 32);
			assertEqualsMod(new int[]{8, 25, 22, 20, 12, 24, 15, 19, 12, 19, 16}, c.coeffs, 32);

			// multiplication without a modulus
			a = new IntegerPolynomial(new int[]{1, 1, 0, 0, -1, -1, 0, 0, -1, 0, 1});
			b = new IntegerPolynomial(new int[]{704, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
			c = a.mult(b);

			// mult(p, modulus) should give the same result as mult(p) followed by modulus
			a = new IntegerPolynomial(new int[]{1, 0, -1, 1, 0, 1, 1, 1, -1, 1, -1});
			b = new IntegerPolynomial(new int[]{0, 1, 1, 0, 0, -1, -1, 1, 1, -1, 1});
			c = a.mult(b);
			c.modPositive(20);
			IntegerPolynomial d = a.mult(b, 20);
			d.modPositive(20);
			assertTrue(Arrays.areEqual(c.coeffs, d.coeffs));
		}

		public virtual void assertEqualsMod(int[] arr1, int[] arr2, int m)
		{
			assertEquals(arr1.Length, arr2.Length);
			for (int i = 0; i < arr1.Length; i++)
			{
				assertEquals((arr1[i] + m) % m, (arr2[i] + m) % m);
			}
		}

		public virtual void testInvertFq()
		{
			SecureRandom random = new SecureRandom();
			// Verify an example from the NTRU tutorial
			IntegerPolynomial a = new IntegerPolynomial(new int[]{-1, 1, 1, 0, -1, 0, 1, 0, 0, 1, -1});
			IntegerPolynomial b = a.invertFq(32);
			assertEqualsMod(new int[]{5, 9, 6, 16, 4, 15, 16, 22, 20, 18, 30}, b.coeffs, 32);
			verifyInverse(a, b, 32);

			// test 3 random polynomials
			int numInvertible = 0;
			while (numInvertible < 3)
			{
				a = DenseTernaryPolynomial.generateRandom(853, random);
				b = a.invertFq(2048);
				if (b != null)
				{
					numInvertible++;
					verifyInverse(a, b, 2048);
				}
			}

			// test a non-invertible polynomial
			a = new IntegerPolynomial(new int[]{-1, 0, 1, 1, 0, 0, -1, 0, -1, 0, 1});
			b = a.invertFq(32);
			assertNull(b);
		}

		public virtual void testInvertF3()
		{
			IntegerPolynomial a = new IntegerPolynomial(new int[]{-1, 1, 1, 0, -1, 0, 1, 0, 0, 1, -1});
			IntegerPolynomial b = a.invertF3();
			assertEqualsMod(new int[]{1, 2, 0, 2, 2, 1, 0, 2, 1, 2, 0}, b.coeffs, 3);
			verifyInverse(a, b, 3);

			// test a non-invertible polynomial
			a = new IntegerPolynomial(new int[]{0, 1, -1, 1, 0, 0, 0, 0, -1, 0, 0});
			b = a.invertF3();
			assertNull(b);
		}

		// tests if a*b=1 (mod modulus)
		private void verifyInverse(IntegerPolynomial a, IntegerPolynomial b, int modulus)
		{
			IntegerPolynomial c = a.mult(b, modulus);
			for (int i = 1; i < c.coeffs.Length; i++)
			{
				c.coeffs[i] %= modulus;
			}
			c.ensurePositive(modulus);
			assertTrue(c.equalsOne());
		}

		public virtual void testFromToBinary()
		{
			byte[] a = new byte[]{(byte)-44, (byte)-33, 30, (byte)-109, 101, (byte)-28, (byte)-6, (byte)-105, (byte)-45, 113, (byte)-72, 99, 101, 15, 9, 49, (byte)-80, (byte)-76, 58, 42, (byte)-57, (byte)-113, (byte)-89, (byte)-14, (byte)-125, 24, 125, (byte)-16, 37, (byte)-58, 10, (byte)-49, (byte)-77, (byte)-31, 120, 103, (byte)-29, 105, (byte)-56, (byte)-126, (byte)-92, 36, 125, 127, (byte)-90, 38, 9, 4, 104, 10, (byte)-78, (byte)-106, (byte)-88, (byte)-1, (byte)-1, (byte)-43, (byte)-19, 90, 41, 0, (byte)-43, 102, 118, (byte)-72, (byte)-122, 19, (byte)-76, 57, (byte)-59, (byte)-2, 35, 47, 83, 114, 86, (byte)-115, (byte)-125, 58, 75, 115, (byte)-29, (byte)-6, 108, 6, (byte)-77, (byte)-51, 127, (byte)-8, (byte)-8, (byte)-58, (byte)-30, (byte)-126, 110, (byte)-5, (byte)-35, (byte)-41, (byte)-37, 69, 22, (byte)-48, 26, 4, (byte)-120, (byte)-19, (byte)-32, (byte)-81, (byte)-77, 124, (byte)-7, (byte)-2, (byte)-46, (byte)-96, 38, (byte)-35, 88, 4, (byte)-5, 16, 101, 29, 7, 2, 88, 35, (byte)-64, 31, (byte)-66, (byte)-70, 120, (byte)-97, 76, (byte)-74, (byte)-97, (byte)-61, 52, (byte)-56, 87, (byte)-35, 5, 95, (byte)-93, (byte)-30, 10, 38, 17, (byte)-102, (byte)-25, 86, 7, (byte)-43, 44, (byte)-52, (byte)-108, 33, (byte)-18, (byte)-110, (byte)-9, (byte)-115, 66, (byte)-71, 66, 1, (byte)-90, (byte)-72, 90, (byte)-88, (byte)-38, 75, 47, (byte)-124, (byte)-120, (byte)-15, (byte)-49, (byte)-8, 85, 5, 17, (byte)-88, 76, 99, (byte)-4, 83, 16, (byte)-91, 82, 116, 112, (byte)-83, 56, (byte)-45, (byte)-26, 125, 13, (byte)-75, (byte)-115, 92, (byte)-12, (byte)-59, 3, (byte)-12, 14, (byte)-6, 43, (byte)-17, 121, 122, 22, 92, (byte)-74, 99, (byte)-59, (byte)-103, 113, 8, (byte)-103, 114, 99, (byte)-48, 92, (byte)-88, 77, 81, 5, 31, (byte)-4, (byte)-69, (byte)-24, 23, 94, 126, 71, 93, 20, 77, 82, (byte)-54, (byte)-14, 86, 45, (byte)-81, 0, 52, (byte)-63, (byte)-66, 48, 104, (byte)-54, 15, (byte)-73, (byte)-2, (byte)-52, 115, 76, 28, (byte)-5, (byte)-94, (byte)-63, 117, (byte)-69, 0, 61, 22, (byte)-1, 71, (byte)-115, 9, (byte)-73, (byte)-100, (byte)-128, (byte)-31, 106, (byte)-74, (byte)-61, (byte)-37, 98, (byte)-6, 11, (byte)-5, 6, (byte)-18, (byte)-53, (byte)-6, 11, (byte)-49, 62, 23, 6, (byte)-128, 38, (byte)-91, 89, (byte)-34, 18, (byte)-38, (byte)-110, (byte)-101, 43, 36, 62, 101, 112, 59, (byte)-91, 78, (byte)-81, 61, 126, (byte)-21, (byte)-42, (byte)-110, (byte)-38, (byte)-27, 69, 57, 9, 24, (byte)-50, (byte)-118, 31, (byte)-17, 42, 87, (byte)-54, 122, (byte)-16, 42, (byte)-47, (byte)-19, (byte)-80, 16, 54, (byte)-97, (byte)-89, 81, (byte)-22, (byte)-35, 45, 54, (byte)-46, 22, (byte)-122, (byte)-95, (byte)-17, 7, (byte)-127, 105, (byte)-100, (byte)-56, (byte)-98, (byte)-105, 101, (byte)-81, 104, 121, (byte)-7, 33, 126, 110, (byte)-125, (byte)-85, 111, (byte)-52, 123, (byte)-98, 41, (byte)-42, 88, (byte)-68, (byte)-17, 39, (byte)-19, (byte)-96, (byte)-10, (byte)-117, 13, (byte)-88, (byte)-75, (byte)-101, (byte)-16, (byte)-7, 73, 23, (byte)-12, 41, (byte)-116, (byte)-105, (byte)-64, (byte)-4, 103, 49, (byte)-15, (byte)-49, 60, 88, (byte)-25, (byte)-21, 42, 26, 95, (byte)-90, (byte)-83, (byte)-69, 64, (byte)-2, 50, (byte)-116, (byte)-64, 26, (byte)-29, (byte)-93, (byte)-120, (byte)-70, 32, (byte)-38, 39, (byte)-126, (byte)-19, 103, 127, 65, 54, 110, 94, 126, (byte)-82, (byte)-80, (byte)-18, 43, 45, 56, (byte)-118, 109, 36, (byte)-8, 10, 113, 69, 53, (byte)-122, (byte)-127, 92, (byte)-127, (byte)-73, 70, (byte)-19, (byte)-105, (byte)-80, (byte)-15, (byte)-5, 99, (byte)-109, (byte)-27, 119, (byte)-76, (byte)-57, (byte)-48, 42, (byte)-35, 23, 39, (byte)-126, 44, (byte)-107, (byte)-100, (byte)-125, 117, (byte)-50, 115, (byte)-79, (byte)-16, 104, 8, (byte)-102, 83, (byte)-73, 21, (byte)-85, 113, (byte)-87, (byte)-54, 93, 63, (byte)-108, (byte)-64, 109, (byte)-74, 15, 14, (byte)-119, (byte)-6, (byte)-68, 45, 37, (byte)-15, (byte)-97, (byte)-95, (byte)-55, 89, 25, (byte)-63, (byte)-92, (byte)-80, (byte)-27, (byte)-8, 55, 50, 96, (byte)-91, 40, (byte)-74, 110, (byte)-96, 94, 6, 85, 92, 0, 34, (byte)-122, 5, (byte)-126, 123, 37, (byte)-90, (byte)-94, 60, 14, 36, 49, (byte)-98, (byte)-23, 57, 75, 63, 106, (byte)-7, (byte)-36, (byte)-89, 84, 71, 60, (byte)-21, 104, (byte)-47, 90, (byte)-52, (byte)-66, 88, (byte)-91, (byte)-81, (byte)-3, 116, 23, 62, (byte)-47, (byte)-84, (byte)-118, 65, 31, 7, (byte)-103, 37, (byte)-29, 115, (byte)-114, 73, 12, (byte)-121, 96, (byte)-91, (byte)-7, 56, 10, (byte)-72, 27, (byte)-45, 122, (byte)-27, (byte)-38, 74, 64, 30, (byte)-60, 64, (byte)-21, 48, 101, 113, 126, (byte)-60, (byte)-103, 71, 100, (byte)-117, 124, (byte)-125, 116, 78, 114, (byte)-74, 42, (byte)-81, (byte)-54, 34, 33, (byte)-10, 19, 23, 24, 40, 0, (byte)-8, 78, 100, 73, (byte)-88, (byte)-95, (byte)-62, (byte)-115, (byte)-18, 47, 10, (byte)-14, (byte)-39, 82, 27, (byte)-9, (byte)-115, (byte)-70, 92, (byte)-6, 39, 45, (byte)-71, (byte)-109, (byte)-41, 94, (byte)-88, (byte)-63, 19, (byte)-58, (byte)-37, (byte)-31, 1, 127, (byte)-42, 125, (byte)-120, (byte)-57, 120, (byte)-86, (byte)-6, 17, (byte)-27, (byte)-37, 47, 55, (byte)-22, (byte)-11, (byte)-31, 38, (byte)-1, 29, 56, (byte)-34, (byte)-104, (byte)-66, (byte)-62, 72, (byte)-11, (byte)-30, (byte)-30, 61, (byte)-31, 10, (byte)-63, 116, (byte)-84, 118, (byte)-127, 6, 17, (byte)-36, 91, 123, 77, 35, 22, 110, 114, 107, (byte)-3, 52, 11, 86, 68, (byte)-56, 0, 119, (byte)-43, (byte)-73, 112, 89, (byte)-4, (byte)-122, (byte)-71, (byte)-26, 103, (byte)-118, (byte)-61, (byte)-112, (byte)-108, (byte)-44, (byte)-25, (byte)-22, 4, 24, 53, (byte)-5, (byte)-71, 9, (byte)-41, 84, (byte)-28, 22, 99, 39, (byte)-26, (byte)-2, (byte)-51, 68, 63, (byte)-15, 99, 66, (byte)-78, 46, (byte)-89, 21, (byte)-38, (byte)-114, (byte)-51, 100, (byte)-59, 84, (byte)-76, (byte)-105, 51, 28, 19, 74, 42, 91, (byte)-73, 12, (byte)-89, (byte)-128, 34, 38, (byte)-100, 121, (byte)-78, 114, (byte)-28, 127, (byte)-29, 50, 105, (byte)-6, 36, 98, (byte)-35, 79, (byte)-58, 5, (byte)-13, (byte)-86, (byte)-101, (byte)-108, (byte)-99, (byte)-70, 25, 103, 63, 57, 79, (byte)-12, (byte)-63, 125, (byte)-54, 61, 15, 6, (byte)-79, 90, 76, 103, (byte)-45, 7, 39, 93, 107, 58, 76, 80, 56, (byte)-108, 55, (byte)-22, 36, 125, (byte)-91, (byte)-65, 11, 69, 10, (byte)-19, (byte)-14, (byte)-4, (byte)-26, (byte)-36, 114, 124, 63, (byte)-31, 88, 92, 108, 33, (byte)-52, (byte)-22, 80, (byte)-65, 57, 126, 43, (byte)-13, 122, (byte)-8, 68, 72, 92, (byte)-50, 100, (byte)-91, 1, (byte)-81, 75, 95, (byte)-11, (byte)-99, 38, 121, (byte)-20, (byte)-70, 82, (byte)-125, (byte)-94, (byte)-18, 16, 59, 89, 18, (byte)-96, 91, (byte)-97, 62, (byte)-96, 127, 45, 70, 16, 84, (byte)-43, (byte)-75, (byte)-118, 81, 58, 84, (byte)-115, (byte)-120, (byte)-3, 41, (byte)-103, (byte)-70, 123, 26, 101, 33, 58, 13, (byte)-11, (byte)-73, (byte)-84, (byte)-47, (byte)-7, 81, (byte)-63, 60, (byte)-45, 30, 100, (byte)-51, (byte)-15, 73, 58, (byte)-119, (byte)-3, 62, (byte)-63, (byte)-17, (byte)-69, (byte)-44, 60, (byte)-54, (byte)-115, (byte)-59, 23, (byte)-59, 98, (byte)-89, (byte)-72, 20, (byte)-96, 27, 53, (byte)-89, 59, (byte)-85, (byte)-29, 120, 23, 62, 8, (byte)-86, 113, 87, (byte)-15, 102, 106, (byte)-104, 57, (byte)-57, 37, 110, 118, 109, 25, 64, 26, (byte)-20, (byte)-86, (byte)-2, 60, (byte)-70, (byte)-33, 67, 13, (byte)-28, (byte)-29, (byte)-63, (byte)-37, 67, 99, 84, 121, (byte)-126, (byte)-38, 45, 24, 122, 51, 11, (byte)-19, (byte)-80, 26, (byte)-106, (byte)-95, 82, 69, (byte)-2, (byte)-75, 62, 106, (byte)-120, 87, (byte)-107, 87, 17, 102, (byte)-52, (byte)-16, 22, 12, (byte)-86, (byte)-48, (byte)-95, (byte)-61, 109, 64, (byte)-29, 111, 40, (byte)-90, (byte)-35, 49, 88, (byte)-15, 122, 127, 87, 113, 116, 93, 100, 28, (byte)-70, (byte)-87, (byte)-40, (byte)-1, (byte)-126, (byte)-114, 7, 79, 16, 2, (byte)-47, (byte)-98, (byte)-102, 49, 58, 61, (byte)-32, 44, 18, (byte)-26, 37, 27, (byte)-123, (byte)-76, 56, 91, 51, (byte)-21, (byte)-48, (byte)-122, (byte)-33, 40, (byte)-8, (byte)-62, (byte)-56, (byte)-126, 91, (byte)-51, 76, (byte)-29, 127, (byte)-22, (byte)-18, (byte)-110, 27, 13, (byte)-111, 81, 51, (byte)-104, 70, 98, 12, 120, (byte)-7, 15, 104, (byte)-43, (byte)-104, 124, 46, 116, 7, (byte)-26, 21, 33, 105, 17, (byte)-99, (byte)-42, (byte)-106, 8, (byte)-85, 39, 8, 79, (byte)-54, (byte)-81, 109, 40, 25, 29, (byte)-18, (byte)-90, 22, 85, (byte)-12, (byte)-16, 61, 49, (byte)-31, 127, 64, 5, 25, 39, (byte)-65, (byte)-42, 13, (byte)-97, (byte)-92, 36, (byte)-126, (byte)-18, (byte)-4, (byte)-22, (byte)-14, 109, (byte)-93, (byte)-76, (byte)-5, 13, 74, 44, 103, 79, 110, 85, 58, 39, (byte)-24, 119, 120, 122, 120, 43, 110, 67, 21, 47, 39, (byte)-48, 7, 91, (byte)-51, 126, 100, (byte)-38, (byte)-124, 0, (byte)-97, 99, (byte)-123, 118, (byte)-27, 8, 102, (byte)-106, (byte)-23, (byte)-53, (byte)-4, (byte)-56, (byte)-9, (byte)-126, (byte)-85, 93, (byte)-4, (byte)-5, 4, 49, 29, 2, 63, 78, (byte)-32, (byte)-106, 118, 111, 52, 54, 74, 53, 106, 39, (byte)-95, (byte)-38, (byte)-18, 118, (byte)-5, 94, (byte)-83, (byte)-97, (byte)-27, 62, (byte)-56, (byte)-90, (byte)-36, 43, 43, (byte)-113, 119, (byte)-89, 44, (byte)-108, (byte)-46, 66, 28, 66, (byte)-38, 3, (byte)-62, (byte)-83, (byte)-35, (byte)-127, (byte)-2, 51, 104, 105, 40, 76, (byte)-10, (byte)-124, (byte)-95, 52, 11, 101, (byte)-32, (byte)-122, (byte)-73, (byte)-17, 37, (byte)-126, 68, (byte)-126, 55, 112, (byte)-126, 38, 99, (byte)-63, 123, (byte)-74, (byte)-31, 58, 8, 93, (byte)-68, 111, (byte)-22, (byte)-24, (byte)-23, 9, (byte)-87, (byte)-25, (byte)-115, 81, (byte)-116, (byte)-91, 60, 96, (byte)-102, (byte)-1, (byte)-7, 73, 99, 46, (byte)-78, 62, 48, (byte)-116, (byte)-52, (byte)-44, (byte)-5, 82, (byte)-45, 5, (byte)-55, (byte)-101, 101, 65, (byte)-109, (byte)-108, 26, 98, (byte)-55, 11, (byte)-86, 57, 30, 92, (byte)-58, 20, 82, 65, 103, 27, (byte)-64, 76, 123, (byte)-56, (byte)-16, (byte)-111, (byte)-83, 125, 65, 111, 9, 123, 14, 119, 126, (byte)-80, 79, 94, (byte)-19, 66, (byte)-25, 35, 112, (byte)-64, 10, (byte)-66, (byte)-86, 51, 56, (byte)-78, 103, 92, (byte)-116, 8, 75, 41, (byte)-49, (byte)-79, (byte)-53, 125, (byte)-32, (byte)-76, (byte)-27, 59, (byte)-8, (byte)-4, (byte)-94, (byte)-104, (byte)-15, 79, (byte)-7, (byte)-124, 32, (byte)-87, (byte)-104, 85, (byte)-118, (byte)-36, 125, 65, 111, (byte)-105, 5, (byte)-105, 40, (byte)-50, 2, 118, 123, (byte)-54, 59, (byte)-22, 94, 20, 99, (byte)-87, (byte)-27, 28, (byte)-30, (byte)-109, 72, (byte)-19, 92, 60, 19, 115, 47, 96, (byte)-96, 10, (byte)-74, 60, 96, (byte)-86, 101, 101, 68, (byte)-44, (byte)-72, 9, (byte)-36, 126, 96, (byte)-45, (byte)-12, 9, 14, (byte)-15, 79, (byte)-79, (byte)-48, 8, (byte)-107, (byte)-81, 47, 35, (byte)-36, (byte)-107, (byte)-120, (byte)-36, (byte)-124, 37, 103, (byte)-60, (byte)-35, (byte)-74, 100, (byte)-38, (byte)-88, (byte)-99, (byte)-99, (byte)-94, (byte)-107, 79, 115, 108, 54, 119, 73, 84, 110, (byte)-74, 92, 57, 108, 80, 47, (byte)-36, (byte)-119, (byte)-115, 58, (byte)-62, (byte)-4, (byte)-97, 43, (byte)-98, 5, 112, 47, 59, (byte)-89, 82, (byte)-69, (byte)-103, 39, (byte)-29, 75, (byte)-9, (byte)-94, (byte)-72, 99, (byte)-64, 22, (byte)-10, 21, 89, 101, 21, 94, (byte)-30, (byte)-17, 73, (byte)-36, (byte)-68, (byte)-89, (byte)-91, (byte)-94, 99, (byte)-106, 119, (byte)-116, 123, (byte)-19, 54, (byte)-99, 64, (byte)-119, 82, 120, (byte)-106, (byte)-99, 80, 69, 29, (byte)-48, 77, 28, 13, 92, (byte)-107, (byte)-77, 94, (byte)-116, 108, 89, (byte)-115, 96, (byte)-41, 25, 99, (byte)-65, 118, (byte)-5, (byte)-16, 48, (byte)-122, 5, 50, (byte)-123, (byte)-115, 13, 24, 7, 15, (byte)-103, (byte)-62, (byte)-71, 92, (byte)-82, (byte)-5, (byte)-70, 49, (byte)-6, (byte)-51, (byte)-17, (byte)-47, 12, 46, (byte)-86, 30, 93, 84, (byte)-101, 43, (byte)-92, (byte)-87, (byte)-118, (byte)-110, (byte)-32, 52, 115, (byte)-4, 36, (byte)-2, (byte)-79, (byte)-69, (byte)-46, (byte)-110, 70, (byte)-82, 6, 21, (byte)-27, (byte)-11, 94, 42, (byte)-81, (byte)-96, 116, (byte)-102, (byte)-38, 36, 32, 91, 28, 80, (byte)-45, 116, (byte)-94, (byte)-33, (byte)-5, (byte)-102, 64, (byte)-96, 27, (byte)-2, 100, (byte)-126, 59, (byte)-71, 33, (byte)-36, (byte)-124, 123, 99, (byte)-76, 108, 127, (byte)-11, (byte)-24, (byte)-19, 84, (byte)-6, 19, 105, (byte)-19, (byte)-18, 120, (byte)-14, 23, 39, 54, 87, 105, 58, (byte)-95, (byte)-15, 127, (byte)-65, 114, 49, 4, (byte)-66, 32, (byte)-7, 84, 43, (byte)-103, 76, 11, 36, (byte)-68, (byte)-3, (byte)-98, (byte)-5, (byte)-43, 35, (byte)-48, 20, (byte)-40, (byte)-33, (byte)-123, 1, (byte)-54, (byte)-44, 99, (byte)-68, 8, (byte)-100, 97, (byte)-49, (byte)-10, 110, 49, 84, 46, (byte)-85, 98, (byte)-103, (byte)-58, (byte)-4, 104, (byte)-100, (byte)-40, (byte)-79, 67, (byte)-20, (byte)-95, 85, 51, 73, 10, (byte)-25, 102, 68, (byte)-97, (byte)-83, (byte)-39, 35, 2, (byte)-111, 71, 62, (byte)-89, 20, 25, (byte)-126, 17, (byte)-81, (byte)-29, 39, (byte)-27, (byte)-55, 55, (byte)-122, 97, 23, (byte)-99, 55, 86, 33, (byte)-9, 8, 55, (byte)-40, (byte)-84, 39, 38, 37, (byte)-29, 87, 113, (byte)-118, (byte)-26, 123, (byte)-95, 24, (byte)-126, 119, (byte)-94, 17, 83, (byte)-43, 10, 63, (byte)-98, 72, 8, 16, (byte)-95, (byte)-96, 119, (byte)-91, 6, 71, (byte)-60, 1, (byte)-77, 4, 53, (byte)-121, 55, 7, 36, (byte)-86, (byte)-49, (byte)-118, (byte)-121, 56, 84, (byte)-49, (byte)-57, (byte)-99, 3, (byte)-68, 37, (byte)-108, (byte)-72, 114, (byte)-74, 120, 3, 121, (byte)-28, (byte)-106, 54, (byte)-20, 63, (byte)-121, (byte)-85, (byte)-59, (byte)-111, 32, 13, (byte)-69, 122, 90, 5, 40, 88, 15, (byte)-90, 125, (byte)-28, 89, 95, 73, 96, 60, (byte)-60, (byte)-51, 102, 7, 57, 91, 59, 15, 92, (byte)-76, (byte)-34, (byte)-23, (byte)-77, 90, 45, 91, 77, (byte)-63, 94, (byte)-127, 74, (byte)-97, (byte)-44, 50, (byte)-87, (byte)-94, (byte)-25, (byte)-71, 112, 127, (byte)-117, 6, 32, (byte)-113, 54, 83, (byte)-31, 111, (byte)-73, 53, 34, (byte)-32, (byte)-98, 125, (byte)-39, 63, 15, 72, (byte)-69, 87, (byte)-118, 108, 17, 84, 15, 61, (byte)-47, 54, (byte)-24, (byte)-79, 91, 28, (byte)-28, 66, 53, 22, 9, (byte)-28, (byte)-12, 38, 64, 75, (byte)-122, 96, (byte)-59, (byte)-45, 4, (byte)-19, 47, (byte)-30, 75, (byte)-94, 62, (byte)-64, 76, (byte)-49, 19, (byte)-66, (byte)-34, 3, 84, (byte)-2, (byte)-54, 13, (byte)-84, 86, (byte)-117, 94, (byte)-27, 89, 16, 96, 52, (byte)-77, (byte)-36, (byte)-116, 27, (byte)-52, (byte)-33, (byte)-50, 14, (byte)-59, 77, 93, (byte)-109, 8, (byte)-89, 81, (byte)-114, (byte)-29, (byte)-94, 73, (byte)-119, (byte)-56, (byte)-19, 88, (byte)-17, (byte)-33, 125, (byte)-18, (byte)-68, 113, 40, (byte)-128, (byte)-112, (byte)-119, (byte)-106, (byte)-106, (byte)-30, 23, (byte)-77, 49, 3, 98, (byte)-101, 99, (byte)-107, (byte)-121, (byte)-12, (byte)-112, 24, (byte)-74, (byte)-74, 79, (byte)-17, 96, 65, (byte)-52, 86, (byte)-63, 45, 84, 119, (byte)-42, 61, (byte)-91, 29, (byte)-87, 65, (byte)-85, 99, (byte)-14, 71, 33, (byte)-41, (byte)-48, (byte)-2, (byte)-121, 78, (byte)-38, 41, (byte)-7, (byte)-37, 48, 122, 61, (byte)-124, 42, (byte)-22, 24, 2, (byte)-49, 74, (byte)-81, (byte)-88, (byte)-89, (byte)-107, 109, 53, (byte)-68, 90, (byte)-117, 123, (byte)-109, (byte)-28, 12, 80, 120, 26, (byte)-104, 73, 70, (byte)-36, 34, (byte)-80, (byte)-104, 23, 16, 14, (byte)-96, (byte)-5, 27, 71, 25, (byte)-8, (byte)-125, 58, 88, (byte)-52, (byte)-97, (byte)-97, (byte)-93, 11, (byte)-44, 116, 42, (byte)-102, (byte)-100, (byte)-31, (byte)-86, 71, 84, 70, 27, 117, (byte)-67, 92, (byte)-84, (byte)-13, 54, (byte)-102, 34, 5, 19, (byte)-76, 71, 89, 22, (byte)-49, (byte)-34, (byte)-29};
			IntegerPolynomial poly = IntegerPolynomial.fromBinary(a, 1499, 2048);
			byte[] b = poly.toBinary(2048);
			// verify that bytes 0..2047 match, ignore non-relevant bits of byte 2048
			assertTrue(Arrays.areEqual(copyOf(a, 2047), copyOf(b, 2047)));
			assertEquals((a[a.Length - 1] & 1) >> (7 - (1499 * 11) % 8), (b[b.Length - 1] & 1) >> (7 - (1499 * 11) % 8));
		}

		public virtual void testFromToBinary3Sves()
		{
			byte[] a = new byte[]{(byte)-112, (byte)-78, 19, 15, 99, (byte)-65, (byte)-56, (byte)-90, 44, (byte)-93, (byte)-109, 104, 40, 90, (byte)-84, (byte)-21, (byte)-124, 51, (byte)-33, 4, (byte)-51, (byte)-106, 33, 86, (byte)-76, 42, 41, (byte)-17, 47, 79, 81, (byte)-29, 15, 116, 101, 120, 116, 32, 116, 111, 32, 101, 110, 99, 114, 121, 112, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
			IntegerPolynomial poly = IntegerPolynomial.fromBinary3Sves(a, 1499);
			byte[] b = poly.toBinary3Sves();
			assertTrue(Arrays.areEqual(a, b));
		}

		public virtual void testFromToBinary3Tight()
		{
			int[] c = new int[]{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, -1, -1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 1, -1, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 1, 0, 1, 0, -1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, -1, -1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0};
			IntegerPolynomial poly1 = new IntegerPolynomial(c);
			IntegerPolynomial poly2 = IntegerPolynomial.fromBinary3Tight(poly1.toBinary3Tight(), c.Length);
			assertTrue(Arrays.areEqual(poly1.coeffs, poly2.coeffs));

			IntegerPolynomial poly3 = new IntegerPolynomial(new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, -1, -1, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, -1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, -1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, -1, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, -1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0});
			byte[] arr = poly3.toBinary3Tight();
			IntegerPolynomial poly4 = IntegerPolynomial.fromBinary3Tight(arr, 1499);
			assertTrue(Arrays.areEqual(poly3.coeffs, poly4.coeffs));

			IntegerPolynomial poly5 = new IntegerPolynomial(new int[]{0, 0, 0, 1, -1, -1, -1});
			arr = poly5.toBinary3Tight();
			IntegerPolynomial poly6 = IntegerPolynomial.fromBinary3Tight(arr, 7);
			assertTrue(Arrays.areEqual(poly5.coeffs, poly6.coeffs));

			SecureRandom random = new SecureRandom();

			for (int i = 0; i < 100; i++)
			{
				IntegerPolynomial poly7 = DenseTernaryPolynomial.generateRandom(157, random);
				arr = poly7.toBinary3Tight();
				IntegerPolynomial poly8 = IntegerPolynomial.fromBinary3Tight(arr, 157);
				assertTrue(Arrays.areEqual(poly7.coeffs, poly8.coeffs));
			}
		}

		public virtual void testResultant()
		{
			SecureRandom random = new SecureRandom();
			NTRUSigningKeyGenerationParameters @params = NTRUSigningKeyGenerationParameters.APR2011_439;
			IntegerPolynomial a = DenseTernaryPolynomial.generateRandom(@params.N, @params.d, @params.d, random);
			verifyResultant(a, a.resultant());

			a = new IntegerPolynomial(new int[]{0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0, 0, 0, 1, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, 0, -1, -1, 0, -1, 1, -1, 0, -1, 0, -1, -1, -1, 0, 0, 0, 1, 1, -1, -1, -1, 0, -1, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 0, 0, 1, 1, -1, 0, 1, -1, 0, 1, 0, 1, 0, -1, -1, 0, 1, 0, -1, 1, 1, 1, 1, 0, 0, -1, -1, 1, 0, 0, -1, -1, 0, -1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, -1, 0, 0, 0, 0, -1, 0, 0, 0, 1, 0, 1, 0, 1, -1, 0, 0, 1, 1, 1, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 1, 0, -1, -1, 0, -1, -1, -1, 0, -1, -1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, -1, 0, 1, 0, -1, 0, 0, 0, 0, 0, 0, -1, -1, 0, -1, -1, 1, 1, 0, 0, -1, 1, 0, 0, 0, -1, 1, -1, 0, -1, 0, 0, 0, -1, 0, 0, 0, 0, 0, -1, 1, 1, 0, 0, -1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, -1, 0, 1, 0, -1, -1, 0, 0, 0, 0, 0, 1, -1, 0, 0, 0, 1, -1, 1, -1, -1, 1, -1, 0, 1, 0, 0, 0, 1, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, -1, 0, 1, -1, 0, 0, 1, 1, 0, 0, 1, 1, 0, -1, 0, -1, 1, -1, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, -1, 0, 0, 1, -1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, -1, 1, 0, -1, -1, 0, 0, -1, 0, 1, 1, -1, 1, -1, 0, 0, 0, 1});
			verifyResultant(a, a.resultant());
		}

		// verifies that res=rho*a mod x^n-1
		private void verifyResultant(IntegerPolynomial a, Resultant r)
		{
			BigIntPolynomial b = (new BigIntPolynomial(a)).mult(r.rho);
			BigInteger[] bCoeffs = b.getCoeffs();

			for (int j = 1; j < bCoeffs.Length - 1; j++)
			{
				assertEquals(BigInteger.ZERO, bCoeffs[j]);
			}
			if (r.res.Equals(BigInteger.ZERO))
			{
				assertEquals(BigInteger.ZERO, bCoeffs[0].subtract(bCoeffs[bCoeffs.Length - 1]));
			}
			else
			{
				assertEquals(BigInteger.ZERO, (bCoeffs[0].subtract(bCoeffs[bCoeffs.Length - 1]).mod(r.res)));
			}
			assertEquals(bCoeffs[0].subtract(r.res), bCoeffs[bCoeffs.Length - 1].negate());
		}

		public virtual void testResultantMod()
		{
			int p = 46337; // prime; must be less than sqrt(2^31) or integer overflows will occur

			IntegerPolynomial a = new IntegerPolynomial(new int[]{0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0, 0, 0, 1, -1, 0, 0, -1, 0, 0, 0, 1, 0, 0, 0, -1, -1, 0, -1, 1, -1, 0, -1, 0, -1, -1, -1, 0, 0, 0, 1, 1, -1, -1, -1, 0, -1, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 0, 0, 1, 1, -1, 0, 1, -1, 0, 1, 0, 1, 0, -1, -1, 0, 1, 0, -1, 1, 1, 1, 1, 0, 0, -1, -1, 1, 0, 0, -1, -1, 0, -1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, -1, 0, 0, 0, 0, -1, 0, 0, 0, 1, 0, 1, 0, 1, -1, 0, 0, 1, 1, 1, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 1, 0, -1, -1, 0, -1, -1, -1, 0, -1, -1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, -1, 0, 1, 0, -1, 0, 0, 0, 0, 0, 0, -1, -1, 0, -1, -1, 1, 1, 0, 0, -1, 1, 0, 0, 0, -1, 1, -1, 0, -1, 0, 0, 0, -1, 0, 0, 0, 0, 0, -1, 1, 1, 0, 0, -1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, -1, 0, 1, 0, -1, -1, 0, 0, 0, 0, 0, 1, -1, 0, 0, 0, 1, -1, 1, -1, -1, 1, -1, 0, 1, 0, 0, 0, 1, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, -1, 0, 1, -1, 0, 0, 1, 1, 0, 0, 1, 1, 0, -1, 0, -1, 1, -1, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, -1, 0, 0, 1, -1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, -1, 1, 0, -1, -1, 0, 0, -1, 0, 1, 1, -1, 1, -1, 0, 0, 0, 1});
			verifyResultant(a, a.resultant(p), p);

			SecureRandom random = new SecureRandom();

			for (int i = 0; i < 10; i++)
			{
				a = DenseTernaryPolynomial.generateRandom(853, random);
				verifyResultant(a, a.resultant(p), p);
			}
		}

		// verifies that res=rho*a mod x^n-1 mod p
		private void verifyResultant(IntegerPolynomial a, Resultant r, int p)
		{
			BigIntPolynomial b = (new BigIntPolynomial(a)).mult(r.rho);
			b.mod(BigInteger.valueOf(p));
			BigInteger[] bCoeffs = b.getCoeffs();

			for (int j = 1; j < bCoeffs.Length - 1; j++)
			{
				assertEquals(BigInteger.ZERO, bCoeffs[j]);
			}
			if (r.res.Equals(BigInteger.ZERO))
			{
				assertEquals(BigInteger.ZERO, bCoeffs[0].subtract(bCoeffs[bCoeffs.Length - 1]));
			}
			else
			{
				assertEquals(BigInteger.ZERO, (bCoeffs[0].subtract(bCoeffs[bCoeffs.Length - 1]).subtract(r.res).mod(BigInteger.valueOf(p))));
			}
			assertEquals(BigInteger.ZERO, bCoeffs[0].subtract(r.res).subtract(bCoeffs[bCoeffs.Length - 1].negate()).mod(BigInteger.valueOf(p)));
		}

		private byte[] copyOf(byte[] src, int length)
		{
			byte[] tmp = new byte[length];
			JavaSystem.arraycopy(src, 0, tmp, 0, tmp.Length);
			return tmp;
		}
	}
}