using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.gmss
{
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// This class provides a specification for the GMSS parameters that are used by
	/// the GMSSKeyPairGenerator and GMSSSignature classes.
	/// </summary>
	/// <seealso cref= org.bouncycastle.pqc.crypto.gmss.GMSSKeyPairGenerator </seealso>
	public class GMSSParameters
	{
		/// <summary>
		/// The number of authentication tree layers.
		/// </summary>
		private int numOfLayers;

		/// <summary>
		/// The height of the authentication trees of each layer.
		/// </summary>
		private int[] heightOfTrees;

		/// <summary>
		/// The Winternitz Parameter 'w' of each layer.
		/// </summary>
		private int[] winternitzParameter;

		/// <summary>
		/// The parameter K needed for the authentication path computation
		/// </summary>
		private int[] K;

		/// <summary>
		/// The constructor for the parameters of the GMSSKeyPairGenerator.
		/// </summary>
		/// <param name="layers">              the number of authentication tree layers </param>
		/// <param name="heightOfTrees">       the height of the authentication trees </param>
		/// <param name="winternitzParameter"> the Winternitz Parameter 'w' of each layer </param>
		/// <param name="K">                   parameter for authpath computation </param>
		public GMSSParameters(int layers, int[] heightOfTrees, int[] winternitzParameter, int[] K)
		{
			init(layers, heightOfTrees, winternitzParameter, K);
		}

		private void init(int layers, int[] heightOfTrees, int[] winternitzParameter, int[] K)
		{
			bool valid = true;
			string errMsg = "";
			this.numOfLayers = layers;
			if ((numOfLayers != winternitzParameter.Length) || (numOfLayers != heightOfTrees.Length) || (numOfLayers != K.Length))
			{
				valid = false;
				errMsg = "Unexpected parameterset format";
			}
			for (int i = 0; i < numOfLayers; i++)
			{
				if ((K[i] < 2) || ((heightOfTrees[i] - K[i]) % 2 != 0))
				{
					valid = false;
					errMsg = "Wrong parameter K (K >= 2 and H-K even required)!";
				}

				if ((heightOfTrees[i] < 4) || (winternitzParameter[i] < 2))
				{
					valid = false;
					errMsg = "Wrong parameter H or w (H > 3 and w > 1 required)!";
				}
			}

			if (valid)
			{
				this.heightOfTrees = Arrays.clone(heightOfTrees);
				this.winternitzParameter = Arrays.clone(winternitzParameter);
				this.K = Arrays.clone(K);
			}
			else
			{
				throw new IllegalArgumentException(errMsg);
			}
		}

		public GMSSParameters(int keySize)
		{
			if (keySize <= 10)
			{ // create 2^10 keys
				int[] defh = new int[] {10};
				int[] defw = new int[] {3};
				int[] defk = new int[] {2};
				this.init(defh.Length, defh, defw, defk);
			}
			else if (keySize <= 20)
			{ // create 2^20 keys
				int[] defh = new int[] {10, 10};
				int[] defw = new int[] {5, 4};
				int[] defk = new int[] {2, 2};
				this.init(defh.Length, defh, defw, defk);
			}
			else
			{ // create 2^40 keys, keygen lasts around 80 seconds
				int[] defh = new int[] {10, 10, 10, 10};
				int[] defw = new int[] {9, 9, 9, 3};
				int[] defk = new int[] {2, 2, 2, 2};
				this.init(defh.Length, defh, defw, defk);
			}
		}

		/// <summary>
		/// Returns the number of levels of the authentication trees.
		/// </summary>
		/// <returns> The number of levels of the authentication trees. </returns>
		public virtual int getNumOfLayers()
		{
			return numOfLayers;
		}

		/// <summary>
		/// Returns the array of height (for each layer) of the authentication trees
		/// </summary>
		/// <returns> The array of height (for each layer) of the authentication trees </returns>
		public virtual int[] getHeightOfTrees()
		{
			return Arrays.clone(heightOfTrees);
		}

		/// <summary>
		/// Returns the array of WinternitzParameter (for each layer) of the
		/// authentication trees
		/// </summary>
		/// <returns> The array of WinternitzParameter (for each layer) of the
		///         authentication trees </returns>
		public virtual int[] getWinternitzParameter()
		{
			return Arrays.clone(winternitzParameter);
		}

		/// <summary>
		/// Returns the parameter K needed for authentication path computation
		/// </summary>
		/// <returns> The parameter K needed for authentication path computation </returns>
		public virtual int[] getK()
		{
			return Arrays.clone(K);
		}
	}

}