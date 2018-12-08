namespace org.bouncycastle.pqc.jcajce.spec
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// This class provides methods for setting and getting the Rainbow-parameters
	/// like number of Vinegar-variables in the layers, number of layers and so on.
	/// <para>
	/// More detailed information about the needed parameters for the Rainbow
	/// Signature Scheme is to be found in the paper of Jintai Ding, Dieter Schmidt:
	/// Rainbow, a New Multivariable Polynomial Signature Scheme. ACNS 2005: 164-175
	/// (http://dx.doi.org/10.1007/11496137_12)
	/// </para>
	/// </summary>
	public class RainbowParameterSpec : AlgorithmParameterSpec
	{

		/// <summary>
		/// DEFAULT PARAMS
		/// </summary>
		/*
		  * Vi = vinegars per layer whereas n is vu (vu = 33 = n) such that
		  *
		  * v1 = 6; o1 = 12-6 = 6
		  *
		  * v2 = 12; o2 = 17-12 = 5
		  *
		  * v3 = 17; o3 = 22-17 = 5
		  *
		  * v4 = 22; o4 = 33-22 = 11
		  *
		  * v5 = 33; (o5 = 0)
		  */
		private static readonly int[] DEFAULT_VI = new int[] {6, 12, 17, 22, 33};

		private int[] vi; // set of vinegar vars per layer.

		/// <summary>
		/// Default Constructor The elements of the array containing the number of
		/// Vinegar variables in each layer are set to the default values here.
		/// </summary>
		public RainbowParameterSpec()
		{
			this.vi = DEFAULT_VI;
		}

		/// <summary>
		/// Constructor with parameters
		/// </summary>
		/// <param name="vi"> The elements of the array containing the number of Vinegar
		///           variables per layer are set to the values of the input array. </param>
		/// <exception cref="IllegalArgumentException"> if the variables are invalid. </exception>
		public RainbowParameterSpec(int[] vi)
		{
			this.vi = vi;

			checkParams();
		}

		private void checkParams()
		{
			if (vi == null)
			{
				throw new IllegalArgumentException("no layers defined.");
			}
			if (vi.Length > 1)
			{
				for (int i = 0; i < vi.Length - 1; i++)
				{
					if (vi[i] >= vi[i + 1])
					{
						throw new IllegalArgumentException("v[i] has to be smaller than v[i+1]");
					}
				}
			}
			else
			{
				throw new IllegalArgumentException("Rainbow needs at least 1 layer, such that v1 < v2.");
			}
		}

		/// <summary>
		/// Getter for the number of layers
		/// </summary>
		/// <returns> the number of layers </returns>
		public virtual int getNumOfLayers()
		{
			return this.vi.Length - 1;
		}

		/// <summary>
		/// Getter for the number of all the polynomials in Rainbow
		/// </summary>
		/// <returns> the number of the polynomials </returns>
		public virtual int getDocumentLength()
		{
			return vi[vi.Length - 1] - vi[0];
		}

		/// <summary>
		/// Getter for the array containing the number of Vinegar-variables per layer
		/// </summary>
		/// <returns> the numbers of vinegars per layer </returns>
		public virtual int[] getVi()
		{
			return Arrays.clone(this.vi);
		}
	}

}