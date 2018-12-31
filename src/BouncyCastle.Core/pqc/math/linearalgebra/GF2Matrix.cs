using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.util;

namespace org.bouncycastle.pqc.math.linearalgebra
{

	
	/// <summary>
	/// This class describes some operations with matrices over finite field GF(2)
	/// and is used in ecc and MQ-PKC (also has some specific methods and
	/// implementation)
	/// </summary>
	public class GF2Matrix : Matrix
	{

		/// <summary>
		/// For the matrix representation the array of type int[][] is used, thus one
		/// element of the array keeps 32 elements of the matrix (from one row and 32
		/// columns)
		/// </summary>
		private int[][] matrix;

		/// <summary>
		/// the length of each array representing a row of this matrix, computed as
		/// <tt>(numColumns + 31) / 32</tt>
		/// </summary>
		private int length;

		/// <summary>
		/// Create the matrix from encoded form.
		/// </summary>
		/// <param name="enc"> the encoded matrix </param>
		public GF2Matrix(byte[] enc)
		{
			if (enc.Length < 9)
			{
				throw new ArithmeticException("given array is not an encoded matrix over GF(2)");
			}

			numRows = LittleEndianConversions.OS2IP(enc, 0);
			numColumns = LittleEndianConversions.OS2IP(enc, 4);

			int n = ((int)((uint)(numColumns + 7) >> 3)) * numRows;

			if ((numRows <= 0) || (n != (enc.Length - 8)))
			{
				throw new ArithmeticException("given array is not an encoded matrix over GF(2)");
			}

			length = (int)((uint)(numColumns + 31) >> 5);

			matrix = RectangularArrays.ReturnRectangularIntArray(numRows, length);

			// number of "full" integer
			int q = numColumns >> 5;
			// number of bits in non-full integer
			int r = numColumns & 0x1f;

			int count = 8;
			for (int i = 0; i < numRows; i++)
			{
				for (int j = 0; j < q; j++, count += 4)
				{
					matrix[i][j] = LittleEndianConversions.OS2IP(enc, count);
				}
				for (int j = 0; j < r; j += 8)
				{
					matrix[i][q] ^= (enc[count++] & 0xff) << j;
				}
			}
		}

		/// <summary>
		/// Create the matrix with the contents of the given array. The matrix is not
		/// copied. Unused coefficients are masked out.
		/// </summary>
		/// <param name="numColumns"> the number of columns </param>
		/// <param name="matrix">     the element array </param>
		public GF2Matrix(int numColumns, int[][] matrix)
		{
			if (matrix[0].Length != (numColumns + 31) >> 5)
			{
				throw new ArithmeticException("Int array does not match given number of columns.");
			}
			this.numColumns = numColumns;
			numRows = matrix.Length;
			length = matrix[0].Length;
			int rest = numColumns & 0x1f;
			int bitMask;
			if (rest == 0)
			{
				bitMask = unchecked((int)0xffffffff);
			}
			else
			{
				bitMask = (1 << rest) - 1;
			}
			for (int i = 0; i < numRows; i++)
			{
				matrix[i][length - 1] &= bitMask;
			}
			this.matrix = matrix;
		}

		/// <summary>
		/// Create an nxn matrix of the given type.
		/// </summary>
		/// <param name="n">            the number of rows (and columns) </param>
		/// <param name="typeOfMatrix"> the martix type (see <seealso cref="Matrix"/> for predefined
		///                     constants) </param>
		public GF2Matrix(int n, char typeOfMatrix) : this(n, typeOfMatrix, new SecureRandom())
		{
		}

		/// <summary>
		/// Create an nxn matrix of the given type.
		/// </summary>
		/// <param name="n">            the matrix size </param>
		/// <param name="typeOfMatrix"> the matrix type </param>
		/// <param name="sr">           the source of randomness </param>
		public GF2Matrix(int n, char typeOfMatrix, SecureRandom sr)
		{
			if (n <= 0)
			{
				throw new ArithmeticException("Size of matrix is non-positive.");
			}

			switch (typeOfMatrix)
			{

			case Matrix.MATRIX_TYPE_ZERO:
				assignZeroMatrix(n, n);
				break;

			case Matrix.MATRIX_TYPE_UNIT:
				assignUnitMatrix(n);
				break;

			case Matrix.MATRIX_TYPE_RANDOM_LT:
				assignRandomLowerTriangularMatrix(n, sr);
				break;

			case Matrix.MATRIX_TYPE_RANDOM_UT:
				assignRandomUpperTriangularMatrix(n, sr);
				break;

			case Matrix.MATRIX_TYPE_RANDOM_REGULAR:
				assignRandomRegularMatrix(n, sr);
				break;

			default:
				throw new ArithmeticException("Unknown matrix type.");
			}
		}

		/// <summary>
		/// Copy constructor.
		/// </summary>
		/// <param name="a"> another <seealso cref="GF2Matrix"/> </param>
		public GF2Matrix(GF2Matrix a)
		{
			numColumns = a.getNumColumns();
			numRows = a.getNumRows();
			length = a.length;
			matrix = new int[a.matrix.Length][];
			for (int i = 0; i < matrix.Length; i++)
			{
				matrix[i] = IntUtils.clone(a.matrix[i]);
			}

		}

		/// <summary>
		/// create the mxn zero matrix
		/// </summary>
		private GF2Matrix(int m, int n)
		{
			if ((n <= 0) || (m <= 0))
			{
				throw new ArithmeticException("size of matrix is non-positive");
			}

			assignZeroMatrix(m, n);
		}

		/// <summary>
		/// Create the mxn zero matrix.
		/// </summary>
		/// <param name="m"> number of rows </param>
		/// <param name="n"> number of columns </param>
		private void assignZeroMatrix(int m, int n)
		{
			numRows = m;
			numColumns = n;
			length = (int)((uint)(n + 31) >> 5);

			matrix = RectangularArrays.ReturnRectangularIntArray(numRows, length);
			for (int i = 0; i < numRows; i++)
			{
				for (int j = 0; j < length; j++)
				{
					matrix[i][j] = 0;
				}
			}
		}

		/// <summary>
		/// Create the mxn unit matrix.
		/// </summary>
		/// <param name="n"> number of rows (and columns) </param>
		private void assignUnitMatrix(int n)
		{
			numRows = n;
			numColumns = n;
			length = (int)((uint)(n + 31) >> 5);

			matrix = RectangularArrays.ReturnRectangularIntArray(numRows, length);
			for (int i = 0; i < numRows; i++)
			{
				for (int j = 0; j < length; j++)
				{
					matrix[i][j] = 0;
				}
			}
			for (int i = 0; i < numRows; i++)
			{
				int rest = i & 0x1f;
				matrix[i][(int)((uint)i >> 5)] = 1 << rest;
			}
		}

		/// <summary>
		/// Create a nxn random lower triangular matrix.
		/// </summary>
		/// <param name="n">  number of rows (and columns) </param>
		/// <param name="sr"> source of randomness </param>
		private void assignRandomLowerTriangularMatrix(int n, SecureRandom sr)
		{
			numRows = n;
			numColumns = n;
			length = (int)((uint)(n + 31) >> 5);

			matrix = RectangularArrays.ReturnRectangularIntArray(numRows, length);
			for (int i = 0; i < numRows; i++)
			{
				int q = (int)((uint)i >> 5);
				int r = i & 0x1f;
				int s = 31 - r;
				r = 1 << r;
				for (int j = 0; j < q; j++)
				{
					matrix[i][j] = sr.nextInt();
				}
				matrix[i][q] = ((int)((uint)sr.nextInt() >> s)) | r;
				for (int j = q + 1; j < length; j++)
				{
					matrix[i][j] = 0;
				}

			}

		}

		/// <summary>
		/// Create a nxn random upper triangular matrix.
		/// </summary>
		/// <param name="n">  number of rows (and columns) </param>
		/// <param name="sr"> source of randomness </param>
		private void assignRandomUpperTriangularMatrix(int n, SecureRandom sr)
		{
			numRows = n;
			numColumns = n;
			length = (int)((uint)(n + 31) >> 5);

			matrix = RectangularArrays.ReturnRectangularIntArray(numRows, length);
			int rest = n & 0x1f;
			int help;
			if (rest == 0)
			{
				help = unchecked((int)0xffffffff);
			}
			else
			{
				help = (1 << rest) - 1;
			}
			for (int i = 0; i < numRows; i++)
			{
				int q = (int)((uint)i >> 5);
				int r = i & 0x1f;
				int s = r;
				r = 1 << r;
				for (int j = 0; j < q; j++)
				{
					matrix[i][j] = 0;
				}
				matrix[i][q] = (sr.nextInt() << s) | r;
				for (int j = q + 1; j < length; j++)
				{
					matrix[i][j] = sr.nextInt();
				}
				matrix[i][length - 1] &= help;
			}

		}

		/// <summary>
		/// Create an nxn random regular matrix.
		/// </summary>
		/// <param name="n">  number of rows (and columns) </param>
		/// <param name="sr"> source of randomness </param>
		private void assignRandomRegularMatrix(int n, SecureRandom sr)
		{
			numRows = n;
			numColumns = n;
			length = (int)((uint)(n + 31) >> 5);

			matrix = RectangularArrays.ReturnRectangularIntArray(numRows, length);
			GF2Matrix lm = new GF2Matrix(n, Matrix.MATRIX_TYPE_RANDOM_LT, sr);
			GF2Matrix um = new GF2Matrix(n, Matrix.MATRIX_TYPE_RANDOM_UT, sr);
			GF2Matrix rm = (GF2Matrix)lm.rightMultiply(um);
			Permutation perm = new Permutation(n, sr);
			int[] p = perm.getVector();
			for (int i = 0; i < n; i++)
			{
				JavaSystem.arraycopy(rm.matrix[i], 0, matrix[p[i]], 0, length);
			}
		}

		/// <summary>
		/// Create a nxn random regular matrix and its inverse.
		/// </summary>
		/// <param name="n">  number of rows (and columns) </param>
		/// <param name="sr"> source of randomness </param>
		/// <returns> the created random regular matrix and its inverse </returns>
		public static GF2Matrix[] createRandomRegularMatrixAndItsInverse(int n, SecureRandom sr)
		{

			GF2Matrix[] result = new GF2Matrix[2];

			// ------------------------------------
			// First part: create regular matrix
			// ------------------------------------

			// ------
			int length = (n + 31) >> 5;
			GF2Matrix lm = new GF2Matrix(n, Matrix.MATRIX_TYPE_RANDOM_LT, sr);
			GF2Matrix um = new GF2Matrix(n, Matrix.MATRIX_TYPE_RANDOM_UT, sr);
			GF2Matrix rm = (GF2Matrix)lm.rightMultiply(um);
			Permutation p = new Permutation(n, sr);
			int[] pVec = p.getVector();


			int[][] matrix = RectangularArrays.ReturnRectangularIntArray(n, length);
			for (int i = 0; i < n; i++)
			{
				JavaSystem.arraycopy(rm.matrix[pVec[i]], 0, matrix[i], 0, length);
			}

			result[0] = new GF2Matrix(n, matrix);

			// ------------------------------------
			// Second part: create inverse matrix
			// ------------------------------------

			// inverse to lm
			GF2Matrix invLm = new GF2Matrix(n, Matrix.MATRIX_TYPE_UNIT);
			for (int i = 0; i < n; i++)
			{
				int rest = i & 0x1f;
				int q = (int)((uint)i >> 5);
				int r = 1 << rest;
				for (int j = i + 1; j < n; j++)
				{
					int b = (lm.matrix[j][q]) & r;
					if (b != 0)
					{
						for (int k = 0; k <= q; k++)
						{
							invLm.matrix[j][k] ^= invLm.matrix[i][k];
						}
					}
				}
			}
			// inverse to um
			GF2Matrix invUm = new GF2Matrix(n, Matrix.MATRIX_TYPE_UNIT);
			for (int i = n - 1; i >= 0; i--)
			{
				int rest = i & 0x1f;
				int q = (int)((uint)i >> 5);
				int r = 1 << rest;
				for (int j = i - 1; j >= 0; j--)
				{
					int b = (um.matrix[j][q]) & r;
					if (b != 0)
					{
						for (int k = q; k < length; k++)
						{
							invUm.matrix[j][k] ^= invUm.matrix[i][k];
						}
					}
				}
			}

			// inverse matrix
			result[1] = (GF2Matrix)invUm.rightMultiply(invLm.rightMultiply(p));

			return result;
		}

		/// <returns> the array keeping the matrix elements </returns>
		public virtual int[][] getIntArray()
		{
			return matrix;
		}

		/// <returns> the length of each array representing a row of this matrix </returns>
		public virtual int getLength()
		{
			return length;
		}

		/// <summary>
		/// Return the row of this matrix with the given index.
		/// </summary>
		/// <param name="index"> the index </param>
		/// <returns> the row of this matrix with the given index </returns>
		public virtual int[] getRow(int index)
		{
			return matrix[index];
		}

		/// <summary>
		/// Returns encoded matrix, i.e., this matrix in byte array form
		/// </summary>
		/// <returns> the encoded matrix </returns>
		public override byte[] getEncoded()
		{
			int n = (int)((uint)(numColumns + 7) >> 3);
			n *= numRows;
			n += 8;
			byte[] enc = new byte[n];

			LittleEndianConversions.I2OSP(numRows, enc, 0);
			LittleEndianConversions.I2OSP(numColumns, enc, 4);

			// number of "full" integer
			int q = (int)((uint)numColumns >> 5);
			// number of bits in non-full integer
			int r = numColumns & 0x1f;

			int count = 8;
			for (int i = 0; i < numRows; i++)
			{
				for (int j = 0; j < q; j++, count += 4)
				{
					LittleEndianConversions.I2OSP(matrix[i][j], enc, count);
				}
				for (int j = 0; j < r; j += 8)
				{
					enc[count++] = unchecked((byte)(((int)((uint)matrix[i][q] >> j)) & 0xff));
				}

			}
			return enc;
		}


		/// <summary>
		/// Returns the percentage of the number of "ones" in this matrix.
		/// </summary>
		/// <returns> the Hamming weight of this matrix (as a ratio). </returns>
		public virtual double getHammingWeight()
		{
			double counter = 0.0;
			double elementCounter = 0.0;
			int rest = numColumns & 0x1f;
			int d;
			if (rest == 0)
			{
				d = length;
			}
			else
			{
				d = length - 1;
			}

			for (int i = 0; i < numRows; i++)
			{

				for (int j = 0; j < d; j++)
				{
				    {int a = matrix[i][j];
					for (int k = 0; k < 32; k++)
					{
						int b = ((int)((uint)a >> k)) & 1;
						counter = counter + b;
						elementCounter = elementCounter + 1;
					}
				    }
                }
			    {int a = matrix[i][length - 1];
				for (int k = 0; k < rest; k++)
				{
					int b = ((int)((uint)a >> k)) & 1;
					counter = counter + b;
					elementCounter = elementCounter + 1;
				}
			}
			}

            return counter / elementCounter;
		}

		/// <summary>
		/// Check if this is the zero matrix (i.e., all entries are zero).
		/// </summary>
		/// <returns> <tt>true</tt> if this is the zero matrix </returns>
		public override bool isZero()
		{
			for (int i = 0; i < numRows; i++)
			{
				for (int j = 0; j < length; j++)
				{
					if (matrix[i][j] != 0)
					{
						return false;
					}
				}
			}
			return true;
		}

		/// <summary>
		/// Get the quadratic submatrix of this matrix consisting of the leftmost
		/// <tt>numRows</tt> columns.
		/// </summary>
		/// <returns> the <tt>(numRows x numRows)</tt> submatrix </returns>
		public virtual GF2Matrix getLeftSubMatrix()
		{
			if (numColumns <= numRows)
			{
				throw new ArithmeticException("empty submatrix");
			}
			int length = (numRows + 31) >> 5;

			int[][] result = RectangularArrays.ReturnRectangularIntArray(numRows, length);
			int bitMask = (1 << (numRows & 0x1f)) - 1;
			if (bitMask == 0)
			{
				bitMask = -1;
			}
			for (int i = numRows - 1; i >= 0; i--)
			{
				JavaSystem.arraycopy(matrix[i], 0, result[i], 0, length);
				result[i][length - 1] &= bitMask;
			}
			return new GF2Matrix(numRows, result);
		}

		/// <summary>
		/// Compute the full form matrix <tt>(this | Id)</tt> from this matrix in
		/// left compact form, where <tt>Id</tt> is the <tt>k x k</tt> identity
		/// matrix and <tt>k</tt> is the number of rows of this matrix.
		/// </summary>
		/// <returns> <tt>(this | Id)</tt> </returns>
		public virtual GF2Matrix extendLeftCompactForm()
		{
			int newNumColumns = numColumns + numRows;
			GF2Matrix result = new GF2Matrix(numRows, newNumColumns);

			int ind = numRows - 1 + numColumns;
			for (int i = numRows - 1; i >= 0; i--, ind--)
			{
				// copy this matrix to first columns
				JavaSystem.arraycopy(matrix[i], 0, result.matrix[i], 0, length);
				// store the identity in last columns
				result.matrix[i][ind >> 5] |= 1 << (ind & 0x1f);
			}

			return result;
		}

		/// <summary>
		/// Get the submatrix of this matrix consisting of the rightmost
		/// <tt>numColumns-numRows</tt> columns.
		/// </summary>
		/// <returns> the <tt>(numRows x (numColumns-numRows))</tt> submatrix </returns>
		public virtual GF2Matrix getRightSubMatrix()
		{
			if (numColumns <= numRows)
			{
				throw new ArithmeticException("empty submatrix");
			}

			int q = numRows >> 5;
			int r = numRows & 0x1f;

			GF2Matrix result = new GF2Matrix(numRows, numColumns - numRows);

			for (int i = numRows - 1; i >= 0; i--)
			{
				// if words have to be shifted
				if (r != 0)
				{
					int ind = q;
					// process all but last word
					for (int j = 0; j < result.length - 1; j++)
					{
						// shift to correct position
						result.matrix[i][j] = ((int)((uint)matrix[i][ind++] >> r)) | (matrix[i][ind] << (32 - r));
					}
					// process last word
					result.matrix[i][result.length - 1] = (int)((uint)matrix[i][ind++] >> r);
					if (ind < length)
					{
						result.matrix[i][result.length - 1] |= matrix[i][ind] << (32 - r);
					}
				}
				else
				{
					// no shifting necessary
					JavaSystem.arraycopy(matrix[i], q, result.matrix[i], 0, result.length);
				}
			}
			return result;
		}

		/// <summary>
		/// Compute the full form matrix <tt>(Id | this)</tt> from this matrix in
		/// right compact form, where <tt>Id</tt> is the <tt>k x k</tt> identity
		/// matrix and <tt>k</tt> is the number of rows of this matrix.
		/// </summary>
		/// <returns> <tt>(Id | this)</tt> </returns>
		public virtual GF2Matrix extendRightCompactForm()
		{
			GF2Matrix result = new GF2Matrix(numRows, numRows + numColumns);

			int q = numRows >> 5;
			int r = numRows & 0x1f;

			for (int i = numRows - 1; i >= 0; i--)
			{
				// store the identity in first columns
				result.matrix[i][i >> 5] |= 1 << (i & 0x1f);

				// copy this matrix to last columns

				// if words have to be shifted
				if (r != 0)
				{
					int ind = q;
					// process all but last word
					for (int j = 0; j < length - 1; j++)
					{
						// obtain matrix word
					    {int mw = matrix[i][j];
						// shift to correct position
						result.matrix[i][ind++] |= mw << r;
						result.matrix[i][ind] |= (int)((uint)mw >> (32 - r));
					    }
                    }
                    // process last word
				    { int mw = matrix[i][length - 1];
					result.matrix[i][ind++] |= mw << r;
					if (ind < result.length)
					{
						result.matrix[i][ind] |= (int)((uint)mw >> (32 - r));
				        }
				    }
                }
				else
				{
					// no shifting necessary
					JavaSystem.arraycopy(matrix[i], 0, result.matrix[i], q, length);
				}
			}

			return result;
		}

		/// <summary>
		/// Compute the transpose of this matrix.
		/// </summary>
		/// <returns> <tt>(this)<sup>T</sup></tt> </returns>
		public virtual Matrix computeTranspose()
		{

			int[][] result = RectangularArrays.ReturnRectangularIntArray(numColumns, (int)((uint)(numRows + 31) >> 5));
			for (int i = 0; i < numRows; i++)
			{
				for (int j = 0; j < numColumns; j++)
				{
					int qs = (int)((uint)j >> 5);
					int rs = j & 0x1f;
					int b = ((int)((uint)matrix[i][qs] >> rs)) & 1;
					int qt = (int)((uint)i >> 5);
					int rt = i & 0x1f;
					if (b == 1)
					{
						result[j][qt] |= 1 << rt;
					}
				}
			}

			return new GF2Matrix(numRows, result);
		}

		/// <summary>
		/// Compute the inverse of this matrix.
		/// </summary>
		/// <returns> the inverse of this matrix (newly created). </returns>
		/// <exception cref="ArithmeticException"> if this matrix is not invertible. </exception>
		public override Matrix computeInverse()
		{
			if (numRows != numColumns)
			{
				throw new ArithmeticException("Matrix is not invertible.");
			}

			// clone this matrix

			int[][] tmpMatrix = RectangularArrays.ReturnRectangularIntArray(numRows, length);
			for (int i = numRows - 1; i >= 0; i--)
			{
				tmpMatrix[i] = IntUtils.clone(matrix[i]);
			}

			// initialize inverse matrix as unit matrix

			int[][] invMatrix = RectangularArrays.ReturnRectangularIntArray(numRows, length);
			for (int i = numRows - 1; i >= 0; i--)
			{
				int q = i >> 5;
				int r = i & 0x1f;
				invMatrix[i][q] = 1 << r;
			}

			// simultaneously compute Gaussian reduction of tmpMatrix and unit
			// matrix
			for (int i = 0; i < numRows; i++)
			{
				// i = q * 32 + (i mod 32)
				int q = i >> 5;
				int bitMask = 1 << (i & 0x1f);
				// if diagonal element is zero
				if ((tmpMatrix[i][q] & bitMask) == 0)
				{
					bool foundNonZero = false;
					// find a non-zero element in the same column
					for (int j = i + 1; j < numRows; j++)
					{
						if ((tmpMatrix[j][q] & bitMask) != 0)
						{
							// found it, swap rows ...
							foundNonZero = true;
							swapRows(tmpMatrix, i, j);
							swapRows(invMatrix, i, j);
							// ... and quit searching
							j = numRows;
							continue;
						}
					}
					// if no non-zero element was found ...
					if (!foundNonZero)
					{
						// ... the matrix is not invertible
						throw new ArithmeticException("Matrix is not invertible.");
					}
				}

				// normalize all but i-th row
				for (int j = numRows - 1; j >= 0; j--)
				{
					if ((j != i) && ((tmpMatrix[j][q] & bitMask) != 0))
					{
						addToRow(tmpMatrix[i], tmpMatrix[j], q);
						addToRow(invMatrix[i], invMatrix[j], 0);
					}
				}
			}

			return new GF2Matrix(numColumns, invMatrix);
		}

		/// <summary>
		/// Compute the product of a permutation matrix (which is generated from an
		/// n-permutation) and this matrix.
		/// </summary>
		/// <param name="p"> the permutation </param>
		/// <returns> <seealso cref="GF2Matrix"/> <tt>P*this</tt> </returns>
		public virtual Matrix leftMultiply(Permutation p)
		{
			int[] pVec = p.getVector();
			if (pVec.Length != numRows)
			{
				throw new ArithmeticException("length mismatch");
			}

			int[][] result = new int[numRows][];

			for (int i = numRows - 1; i >= 0; i--)
			{
				result[i] = IntUtils.clone(matrix[pVec[i]]);
			}

			return new GF2Matrix(numRows, result);
		}

		/// <summary>
		/// compute product a row vector and this matrix
		/// </summary>
		/// <param name="vec"> a vector over GF(2) </param>
		/// <returns> Vector product a*matrix </returns>
		public override Vector leftMultiply(Vector vec)
		{

			if (!(vec is GF2Vector))
			{
				throw new ArithmeticException("vector is not defined over GF(2)");
			}

			if (vec.length != numRows)
			{
				throw new ArithmeticException("length mismatch");
			}

			int[] v = ((GF2Vector)vec).getVecArray();
			int[] res = new int[length];

			int q = numRows >> 5;
			int r = 1 << (numRows & 0x1f);

			// compute scalar products with full words of vector
			int row = 0;
			for (int i = 0; i < q; i++)
			{
			{
				int bitMask = 1;
				do
				{
					int b = v[i] & bitMask;
					if (b != 0)
					{
						for (int j = 0; j < length; j++)
						{
							res[j] ^= matrix[row][j];
						}
					}
					row++;
					bitMask <<= 1;
				} while (bitMask != 0);
			}
			}

            // compute scalar products with last word of vector
			{
            int bitMask = 1;
			while (bitMask != r)
			{
				int b = v[q] & bitMask;
				if (b != 0)
				{
					for (int j = 0; j < length; j++)
					{
						res[j] ^= matrix[row][j];
					}
				}
				row++;
				bitMask <<= 1;
			}

			return new GF2Vector(res, numColumns);
		    }
		}

        /// <summary>
        /// Compute the product of the matrix <tt>(this | Id)</tt> and a column
        /// vector, where <tt>Id</tt> is a <tt>(numRows x numRows)</tt> unit
        /// matrix.
        /// </summary>
        /// <param name="vec"> the vector over GF(2) </param>
        /// <returns> <tt>(this | Id)*vector</tt> </returns>
        public virtual Vector leftMultiplyLeftCompactForm(Vector vec)
		{
			if (!(vec is GF2Vector))
			{
				throw new ArithmeticException("vector is not defined over GF(2)");
			}

			if (vec.length != numRows)
			{
				throw new ArithmeticException("length mismatch");
			}

			int[] v = ((GF2Vector)vec).getVecArray();
			int[] res = new int[(int)((uint)(numRows + numColumns + 31) >> 5)];

			// process full words of vector
			int words = (int)((uint)numRows >> 5);
			int row = 0;
			for (int i = 0; i < words; i++)
			{
			    {
                    int bitMask = 1;
				do
				{
					int b = v[i] & bitMask;
					if (b != 0)
					{
						// compute scalar product part
						for (int j = 0; j < length; j++)
						{
							res[j] ^= matrix[row][j];
						}
						// set last bit
						int q = (int)((uint)(numColumns + row) >> 5);
						int r = (numColumns + row) & 0x1f;
						res[q] |= 1 << r;
					}
					row++;
					bitMask <<= 1;
				} while (bitMask != 0);
			}
			}

			{
            // process last word of vector
                int rem = 1 << (numRows & 0x1f);
			int bitMask = 1;
			while (bitMask != rem)
			{
				int b = v[words] & bitMask;
				if (b != 0)
				{
					// compute scalar product part
					for (int j = 0; j < length; j++)
					{
						res[j] ^= matrix[row][j];
					}
					// set last bit
					int q = (int)((uint)(numColumns + row) >> 5);
					int r = (numColumns + row) & 0x1f;
					res[q] |= 1 << r;
				}
				row++;
				bitMask <<= 1;
			}

			return new GF2Vector(res, numRows + numColumns);
		}
		}

        /// <summary>
        /// Compute the product of this matrix and a matrix A over GF(2).
        /// </summary>
        /// <param name="mat"> a matrix A over GF(2) </param>
        /// <returns> matrix product <tt>this*matrixA</tt> </returns>
        public override Matrix rightMultiply(Matrix mat)
		{
			if (!(mat is GF2Matrix))
			{
				throw new ArithmeticException("matrix is not defined over GF(2)");
			}

			if (mat.numRows != numColumns)
			{
				throw new ArithmeticException("length mismatch");
			}

			GF2Matrix a = (GF2Matrix)mat;
			GF2Matrix result = new GF2Matrix(numRows, mat.numColumns);

			int d;
			int rest = numColumns & 0x1f;
			if (rest == 0)
			{
				d = length;
			}
			else
			{
				d = length - 1;
			}
			for (int i = 0; i < numRows; i++)
			{
				int count = 0;
				for (int j = 0; j < d; j++)
				{
				    {
                        int e = matrix[i][j];
					for (int h = 0; h < 32; h++)
					{
						int b = e & (1 << h);
						if (b != 0)
						{
							for (int g = 0; g < a.length; g++)
							{
								result.matrix[i][g] ^= a.matrix[count][g];
							}
						}
						count++;
					}
				}
				}
				{
                int e = matrix[i][length - 1];
				for (int h = 0; h < rest; h++)
				{
					int b = e & (1 << h);
					if (b != 0)
					{
						for (int g = 0; g < a.length; g++)
						{
							result.matrix[i][g] ^= a.matrix[count][g];
						}
					}
					count++;
				}

			}

		    }
		    return result;
		}

        /// <summary>
        /// Compute the product of this matrix and a permutation matrix which is
        /// generated from an n-permutation.
        /// </summary>
        /// <param name="p"> the permutation </param>
        /// <returns> <seealso cref="GF2Matrix"/> <tt>this*P</tt> </returns>
        public override Matrix rightMultiply(Permutation p)
		{

			int[] pVec = p.getVector();
			if (pVec.Length != numColumns)
			{
				throw new ArithmeticException("length mismatch");
			}

			GF2Matrix result = new GF2Matrix(numRows, numColumns);

			for (int i = numColumns - 1; i >= 0; i--)
			{
				int q = (int)((uint)i >> 5);
				int r = i & 0x1f;
				int pq = (int)((uint)pVec[i] >> 5);
				int pr = pVec[i] & 0x1f;
				for (int j = numRows - 1; j >= 0; j--)
				{
					result.matrix[j][q] |= (((int)((uint)matrix[j][pq] >> pr)) & 1) << r;
				}
			}

			return result;
		}

		/// <summary>
		/// Compute the product of this matrix and the given column vector.
		/// </summary>
		/// <param name="vec"> the vector over GF(2) </param>
		/// <returns> <tt>this*vector</tt> </returns>
		public override Vector rightMultiply(Vector vec)
		{
			if (!(vec is GF2Vector))
			{
				throw new ArithmeticException("vector is not defined over GF(2)");
			}

			if (vec.length != numColumns)
			{
				throw new ArithmeticException("length mismatch");
			}

			int[] v = ((GF2Vector)vec).getVecArray();
			int[] res = new int[(int)((uint)(numRows + 31) >> 5)];

			for (int i = 0; i < numRows; i++)
			{
				// compute full word scalar products
				int help = 0;
				for (int j = 0; j < length; j++)
				{
					help ^= matrix[i][j] & v[j];
				}
				// compute single word scalar product
				int bitValue = 0;
				for (int j = 0; j < 32; j++)
				{
					bitValue ^= ((int)((uint)help >> j)) & 1;
				}
				// set result bit
				if (bitValue == 1)
				{
					res[(int)((uint)i >> 5)] |= 1 << (i & 0x1f);
				}
			}

			return new GF2Vector(res, numRows);
		}

		/// <summary>
		/// Compute the product of the matrix <tt>(Id | this)</tt> and a column
		/// vector, where <tt>Id</tt> is a <tt>(numRows x numRows)</tt> unit
		/// matrix.
		/// </summary>
		/// <param name="vec"> the vector over GF(2) </param>
		/// <returns> <tt>(Id | this)*vector</tt> </returns>
		public virtual Vector rightMultiplyRightCompactForm(Vector vec)
		{
			if (!(vec is GF2Vector))
			{
				throw new ArithmeticException("vector is not defined over GF(2)");
			}

			if (vec.length != numColumns + numRows)
			{
				throw new ArithmeticException("length mismatch");
			}

			int[] v = ((GF2Vector)vec).getVecArray();
			int[] res = new int[(int)((uint)(numRows + 31) >> 5)];

			int q = numRows >> 5;
			int r = numRows & 0x1f;

			// for all rows
			for (int i = 0; i < numRows; i++)
			{
				// get vector bit
				int help = ((int)((uint)v[i >> 5] >> (i & 0x1f))) & 1;

				// compute full word scalar products
				int vInd = q;
				// if words have to be shifted
				if (r != 0)
				{
					int vw = 0;
					// process all but last word
					for (int j = 0; j < length - 1; j++)
					{
						// shift to correct position
						vw = ((int)((uint)v[vInd++] >> r)) | (v[vInd] << (32 - r));
						help ^= matrix[i][j] & vw;
					}
					// process last word
					vw = (int)((uint)v[vInd++] >> r);
					if (vInd < v.Length)
					{
						vw |= v[vInd] << (32 - r);
					}
					help ^= matrix[i][length - 1] & vw;
				}
				else
				{
					// no shifting necessary
					for (int j = 0; j < length; j++)
					{
						help ^= matrix[i][j] & v[vInd++];
					}
				}

				// compute single word scalar product
				int bitValue = 0;
				for (int j = 0; j < 32; j++)
				{
					bitValue ^= help & 1;
					help = (int)((uint)help >> 1);
				}

				// set result bit
				if (bitValue == 1)
				{
					res[i >> 5] |= 1 << (i & 0x1f);
				}
			}

			return new GF2Vector(res, numRows);
		}

		/// <summary>
		/// Compare this matrix with another object.
		/// </summary>
		/// <param name="other"> another object </param>
		/// <returns> the result of the comparison </returns>
		public override bool Equals(object other)
		{

			if (!(other is GF2Matrix))
			{
				return false;
			}
			GF2Matrix otherMatrix = (GF2Matrix)other;

			if ((numRows != otherMatrix.numRows) || (numColumns != otherMatrix.numColumns) || (length != otherMatrix.length))
			{
				return false;
			}

			for (int i = 0; i < numRows; i++)
			{
				if (!IntUtils.Equals(matrix[i], otherMatrix.matrix[i]))
				{
					return false;
				}
			}

			return true;
		}

		/// <returns> the hash code of this matrix </returns>
		public override int GetHashCode()
		{
			int hash = (numRows * 31 + numColumns) * 31 + length;
			for (int i = 0; i < numRows; i++)
			{
				hash = hash * 31 + Arrays.GetHashCode(matrix[i]);
			}
			return hash;
		}

		/// <returns> a human readable form of the matrix </returns>
		public override string ToString()
		{
			int rest = numColumns & 0x1f;
			int d;
			if (rest == 0)
			{
				d = length;
			}
			else
			{
				d = length - 1;
			}

			StringBuffer buf = new StringBuffer();
			for (int i = 0; i < numRows; i++)
			{
				buf.append(i + ": ");
				for (int j = 0; j < d; j++)
				{
				    {
                        int a = matrix[i][j];
					for (int k = 0; k < 32; k++)
					{
						int b = ((int)((uint)a >> k)) & 1;
						if (b == 0)
						{
							buf.append('0');
						}
						else
						{
							buf.append('1');
						}
					}
					buf.append(' ');
				}
				}
				{
                int a = matrix[i][length - 1];
				for (int k = 0; k < rest; k++)
				{
					int b = ((int)((uint)a >> k)) & 1;
					if (b == 0)
					{
						buf.append('0');
					}
					else
					{
						buf.append('1');
					}
				}
				buf.append('\n');
			}
		}

			return buf.ToString();
    }

    /// <summary>
    /// Swap two rows of the given matrix.
    /// </summary>
    /// <param name="matrix"> the matrix </param>
    /// <param name="first">  the index of the first row </param>
    /// <param name="second"> the index of the second row </param>
    private static void swapRows(int[][] matrix, int first, int second)
		{
			int[] tmp = matrix[first];
			matrix[first] = matrix[second];
			matrix[second] = tmp;
		}

		/// <summary>
		/// Partially add one row to another.
		/// </summary>
		/// <param name="fromRow">    the addend </param>
		/// <param name="toRow">      the row to add to </param>
		/// <param name="startIndex"> the array index to start from </param>
		private static void addToRow(int[] fromRow, int[] toRow, int startIndex)
		{
			for (int i = toRow.Length - 1; i >= startIndex; i--)
			{
				toRow[i] = fromRow[i] ^ toRow[i];
			}
		}

	}

}