using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.crypto.rainbow.util
{
	/// <summary>
	/// This class offers different operations on matrices in field GF2^8.
	/// <para>
	/// Implemented are functions:
	/// - finding inverse of a matrix
	/// - solving linear equation systems using the Gauss-Elimination method
	/// - basic operations like matrix multiplication, addition and so on.
	/// </para>
	/// </summary>

	public class ComputeInField
	{

		private short[][] A; // used by solveEquation and inverse
		internal short[] x;

		/// <summary>
		/// Constructor with no parameters
		/// </summary>
		public ComputeInField()
		{
		}


		/// <summary>
		/// This function finds a solution of the equation Bx = b.
		/// Exception is thrown if the linear equation system has no solution
		/// </summary>
		/// <param name="B"> this matrix is the left part of the
		///          equation (B in the equation above) </param>
		/// <param name="b"> the right part of the equation
		///          (b in the equation above) </param>
		/// <returns> x  the solution of the equation if it is solvable
		/// null otherwise </returns>
		/// <exception cref="RuntimeException"> if LES is not solvable </exception>
		public virtual short[] solveEquation(short[][] B, short[] b)
		{
			if (B.Length != b.Length)
			{
				return null; // not solvable in this form
			}

			try
			{


				/// <summary>
				/// initialize * </summary>
				// this matrix stores B and b from the equation B*x = b
				// b is stored as the last column.
				// B contains one column more than rows.
				// In this column we store a free coefficient that should be later subtracted from b

				A = RectangularArrays.ReturnRectangularShortArray(B.Length, B.Length + 1);
				// stores the solution of the LES
				x = new short[B.Length];

				/// <summary>
				/// copy B into the global matrix A * </summary>
				for (int i = 0; i < B.Length; i++)
				{ // rows
					for (int j = 0; j < B[0].Length; j++)
					{ // cols
						A[i][j] = B[i][j];
					}
				}

				/// <summary>
				/// copy the vector b into the global A * </summary>
				//the free coefficient, stored in the last column of A( A[i][b.length]
				// is to be subtracted from b
				for (int i = 0; i < b.Length; i++)
				{
					A[i][b.Length] = GF2Field.addElem(b[i], A[i][b.Length]);
				}

				/// <summary>
				/// call the methods for gauss elimination and backward substitution * </summary>
				computeZerosUnder(false); // obtain zeros under the diagonal
				substitute();

				return x;

			}
			catch (RuntimeException)
			{
				return null; // the LES is not solvable!
			}
		}

		/// <summary>
		/// This function computes the inverse of a given matrix using the Gauss-
		/// Elimination method.
		/// <para>
		/// An exception is thrown if the matrix has no inverse
		/// 
		/// </para>
		/// </summary>
		/// <param name="coef"> the matrix which inverse matrix is needed </param>
		/// <returns> inverse matrix of the input matrix.
		/// If the matrix is singular, null is returned. </returns>
		/// <exception cref="RuntimeException"> if the given matrix is not invertible </exception>
		public virtual short[][] inverse(short[][] coef)
		{
			try
			{
				/// <summary>
				/// Initialization: * </summary>
				short factor;
				short[][] inverse;

				A = RectangularArrays.ReturnRectangularShortArray(coef.Length, 2 * coef.Length);
				if (coef.Length != coef[0].Length)
				{
					throw new RuntimeException("The matrix is not invertible. Please choose another one!");
				}

				/// <summary>
				/// prepare: Copy coef and the identity matrix into the global A. * </summary>
				for (int i = 0; i < coef.Length; i++)
				{
					for (int j = 0; j < coef.Length; j++)
					{
						//copy the input matrix coef into A
						A[i][j] = coef[i][j];
					}
					// copy the identity matrix into A.
					for (int j = coef.Length; j < 2 * coef.Length; j++)
					{
						A[i][j] = 0;
					}
					A[i][i + A.Length] = 1;
				}

				/// <summary>
				/// Elimination operations to get the identity matrix from the left side of A. * </summary>
				// modify A to get 0s under the diagonal.
				computeZerosUnder(true);

				// modify A to get only 1s on the diagonal: A[i][j] =A[i][j]/A[i][i].
				for (int i = 0; i < A.Length; i++)
				{
					factor = GF2Field.invElem(A[i][i]);
					for (int j = i; j < 2 * A.Length; j++)
					{
						A[i][j] = GF2Field.multElem(A[i][j], factor);
					}
				}

				//modify A to get only 0s above the diagonal.
				computeZerosAbove();

				// copy the result (the second half of A) in the matrix inverse.

				inverse = RectangularArrays.ReturnRectangularShortArray(A.Length, A.Length);
				for (int i = 0; i < A.Length; i++)
				{
					for (int j = A.Length; j < 2 * A.Length; j++)
					{
						inverse[i][j - A.Length] = A[i][j];
					}
				}
				return inverse;

			}
			catch (RuntimeException)
			{
				// The matrix is not invertible! A new one should be generated!
				return null;
			}
		}

		/// <summary>
		/// Elimination under the diagonal.
		/// This function changes a matrix so that it contains only zeros under the
		/// diagonal(Ai,i) using only Gauss-Elimination operations.
		/// <para>
		/// It is used in solveEquaton as well as in the function for
		/// finding an inverse of a matrix: {@link}inverse. Both of them use the
		/// Gauss-Elimination Method.
		/// </para>
		/// </para><para>
		/// The result is stored in the global matrix A
		/// </p>
		/// </summary>
		/// <param name="usedForInverse"> This parameter shows if the function is used by the
		///                       solveEquation-function or by the inverse-function and according
		///                       to this creates matrices of different sizes. </param>
		/// <exception cref="RuntimeException"> in case a multiplicative inverse of 0 is needed </exception>
		private void computeZerosUnder(bool usedForInverse)
		{

			//the number of columns in the global A where the tmp results are stored
			int length;
			short tmp = 0;

			//the function is used in inverse() - A should have 2 times more columns than rows
			if (usedForInverse)
			{
				length = 2 * A.Length;
			}
			//the function is used in solveEquation - A has 1 column more than rows
			else
			{
				length = A.Length + 1;
			}

			//elimination operations to modify A so that that it contains only 0s under the diagonal
			for (int k = 0; k < A.Length - 1; k++)
			{ // the fixed row
				for (int i = k + 1; i < A.Length; i++)
				{ // rows
					short factor1 = A[i][k];
					short factor2 = GF2Field.invElem(A[k][k]);

					//The element which multiplicative inverse is needed, is 0
					//in this case is the input matrix not invertible
					if (factor2 == 0)
					{
						throw new IllegalStateException("Matrix not invertible! We have to choose another one!");
					}

					for (int j = k; j < length; j++)
					{ // columns
						// tmp=A[k,j] / A[k,k]
						tmp = GF2Field.multElem(A[k][j], factor2);
						// tmp = A[i,k] * A[k,j] / A[k,k]
						tmp = GF2Field.multElem(factor1, tmp);
						// A[i,j]=A[i,j]-A[i,k]/A[k,k]*A[k,j];
						A[i][j] = GF2Field.addElem(A[i][j], tmp);
					}
				}
			}
		}

		/// <summary>
		/// Elimination above the diagonal.
		/// This function changes a matrix so that it contains only zeros above the
		/// diagonal(Ai,i) using only Gauss-Elimination operations.
		/// <para>
		/// It is used in the inverse-function
		/// The result is stored in the global matrix A
		/// </para>
		/// </summary>
		/// <exception cref="RuntimeException"> in case a multiplicative inverse of 0 is needed </exception>
		private void computeZerosAbove()
		{
			short tmp = 0;
			for (int k = A.Length - 1; k > 0; k--)
			{ // the fixed row
				for (int i = k - 1; i >= 0; i--)
				{ // rows
					short factor1 = A[i][k];
					short factor2 = GF2Field.invElem(A[k][k]);
					if (factor2 == 0)
					{
						throw new RuntimeException("The matrix is not invertible");
					}
					for (int j = k; j < 2 * A.Length; j++)
					{ // columns
						// tmp = A[k,j] / A[k,k]
						tmp = GF2Field.multElem(A[k][j], factor2);
						// tmp = A[i,k] * A[k,j] / A[k,k]
						tmp = GF2Field.multElem(factor1, tmp);
						// A[i,j] = A[i,j] - A[i,k] / A[k,k] * A[k,j];
						A[i][j] = GF2Field.addElem(A[i][j], tmp);
					}
				}
			}
		}


		/// <summary>
		/// This function uses backward substitution to find x
		/// of the linear equation system (LES) B*x = b,
		/// where A a triangle-matrix is (contains only zeros under the diagonal)
		/// and b is a vector
		/// <para>
		/// If the multiplicative inverse of 0 is needed, an exception is thrown.
		/// In this case is the LES not solvable
		/// </para>
		/// </summary>
		/// <exception cref="RuntimeException"> in case a multiplicative inverse of 0 is needed </exception>
		private void substitute()
		{

			// for the temporary results of the operations in field
			short tmp, temp;

			temp = GF2Field.invElem(A[A.Length - 1][A.Length - 1]);
			if (temp == 0)
			{
				throw new IllegalStateException("The equation system is not solvable");
			}

			/// <summary>
			/// backward substitution * </summary>
			x[A.Length - 1] = GF2Field.multElem(A[A.Length - 1][A.Length], temp);
			for (int i = A.Length - 2; i >= 0; i--)
			{
				tmp = A[i][A.Length];
				for (int j = A.Length - 1; j > i; j--)
				{
					temp = GF2Field.multElem(A[i][j], x[j]);
					tmp = GF2Field.addElem(tmp, temp);
				}

				temp = GF2Field.invElem(A[i][i]);
				if (temp == 0)
				{
					throw new IllegalStateException("Not solvable equation system");
				}
				x[i] = GF2Field.multElem(tmp, temp);
			}
		}


		/// <summary>
		/// This function multiplies two given matrices.
		/// If the given matrices cannot be multiplied due
		/// to different sizes, an exception is thrown.
		/// </summary>
		/// <param name="M1"> -the 1st matrix </param>
		/// <param name="M2"> -the 2nd matrix </param>
		/// <returns> A = M1*M2 </returns>
		/// <exception cref="RuntimeException"> in case the given matrices cannot be multiplied
		/// due to different dimensions. </exception>
		public virtual short[][] multiplyMatrix(short[][] M1, short[][] M2)
		{

			if (M1[0].Length != M2.Length)
			{
				throw new RuntimeException("Multiplication is not possible!");
			}
			short tmp = 0;

			A = RectangularArrays.ReturnRectangularShortArray(M1.Length, M2[0].Length);
			for (int i = 0; i < M1.Length; i++)
			{
				for (int j = 0; j < M2.Length; j++)
				{
					for (int k = 0; k < M2[0].Length; k++)
					{
						tmp = GF2Field.multElem(M1[i][j], M2[j][k]);
						A[i][k] = GF2Field.addElem(A[i][k], tmp);
					}
				}
			}
			return A;
		}

		/// <summary>
		/// This function multiplies a given matrix with a one-dimensional array.
		/// <para>
		/// An exception is thrown, if the number of columns in the matrix and
		/// the number of rows in the one-dim. array differ.
		/// 
		/// </para>
		/// </summary>
		/// <param name="M1"> the matrix to be multiplied </param>
		/// <param name="m">  the one-dimensional array to be multiplied </param>
		/// <returns> M1*m </returns>
		/// <exception cref="RuntimeException"> in case of dimension inconsistency </exception>
		public virtual short[] multiplyMatrix(short[][] M1, short[] m)
		{
			if (M1[0].Length != m.Length)
			{
				throw new RuntimeException("Multiplication is not possible!");
			}
			short tmp = 0;
			short[] B = new short[M1.Length];
			for (int i = 0; i < M1.Length; i++)
			{
				for (int j = 0; j < m.Length; j++)
				{
					tmp = GF2Field.multElem(M1[i][j], m[j]);
					B[i] = GF2Field.addElem(B[i], tmp);
				}
			}
			return B;
		}

		/// <summary>
		/// Addition of two vectors
		/// </summary>
		/// <param name="vector1"> first summand, always of dim n </param>
		/// <param name="vector2"> second summand, always of dim n </param>
		/// <returns> addition of vector1 and vector2 </returns>
		/// <exception cref="RuntimeException"> in case the addition is impossible
		/// due to inconsistency in the dimensions </exception>
		public virtual short[] addVect(short[] vector1, short[] vector2)
		{
			if (vector1.Length != vector2.Length)
			{
				throw new RuntimeException("Multiplication is not possible!");
			}
			short[] rslt = new short[vector1.Length];
			for (int n = 0; n < rslt.Length; n++)
			{
				rslt[n] = GF2Field.addElem(vector1[n], vector2[n]);
			}
			return rslt;
		}

		/// <summary>
		/// Multiplication of column vector with row vector
		/// </summary>
		/// <param name="vector1"> column vector, always n x 1 </param>
		/// <param name="vector2"> row vector, always 1 x n </param>
		/// <returns> resulting n x n matrix of multiplication </returns>
		/// <exception cref="RuntimeException"> in case the multiplication is impossible due to
		/// inconsistency in the dimensions </exception>
		public virtual short[][] multVects(short[] vector1, short[] vector2)
		{
			if (vector1.Length != vector2.Length)
			{
				throw new RuntimeException("Multiplication is not possible!");
			}

			short[][] rslt = RectangularArrays.ReturnRectangularShortArray(vector1.Length, vector2.Length);
			for (int i = 0; i < vector1.Length; i++)
			{
				for (int j = 0; j < vector2.Length; j++)
				{
					rslt[i][j] = GF2Field.multElem(vector1[i], vector2[j]);
				}
			}
			return rslt;
		}

		/// <summary>
		/// Multiplies vector with scalar
		/// </summary>
		/// <param name="scalar"> galois element to multiply vector with </param>
		/// <param name="vector"> vector to be multiplied </param>
		/// <returns> vector multiplied with scalar </returns>
		public virtual short[] multVect(short scalar, short[] vector)
		{
			short[] rslt = new short[vector.Length];
			for (int n = 0; n < rslt.Length; n++)
			{
				rslt[n] = GF2Field.multElem(scalar, vector[n]);
			}
			return rslt;
		}

		/// <summary>
		/// Multiplies matrix with scalar
		/// </summary>
		/// <param name="scalar"> galois element to multiply matrix with </param>
		/// <param name="matrix"> 2-dim n x n matrix to be multiplied </param>
		/// <returns> matrix multiplied with scalar </returns>
		public virtual short[][] multMatrix(short scalar, short[][] matrix)
		{

			short[][] rslt = RectangularArrays.ReturnRectangularShortArray(matrix.Length, matrix[0].Length);
			for (int i = 0; i < matrix.Length; i++)
			{
				for (int j = 0; j < matrix[0].Length; j++)
				{
					rslt[i][j] = GF2Field.multElem(scalar, matrix[i][j]);
				}
			}
			return rslt;
		}

		/// <summary>
		/// Adds the n x n matrices matrix1 and matrix2
		/// </summary>
		/// <param name="matrix1"> first summand </param>
		/// <param name="matrix2"> second summand </param>
		/// <returns> addition of matrix1 and matrix2; both having the dimensions n x n </returns>
		/// <exception cref="RuntimeException"> in case the addition is not possible because of
		/// different dimensions of the matrices </exception>
		public virtual short[][] addSquareMatrix(short[][] matrix1, short[][] matrix2)
		{
			if (matrix1.Length != matrix2.Length || matrix1[0].Length != matrix2[0].Length)
			{
				throw new RuntimeException("Addition is not possible!");
			}


			short[][] rslt = RectangularArrays.ReturnRectangularShortArray(matrix1.Length, matrix1.Length);
			for (int i = 0; i < matrix1.Length; i++)
			{
				for (int j = 0; j < matrix2.Length; j++)
				{
					rslt[i][j] = GF2Field.addElem(matrix1[i][j], matrix2[i][j]);
				}
			}
			return rslt;
		}

	}

}