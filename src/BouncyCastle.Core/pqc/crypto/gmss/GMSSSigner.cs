using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.crypto.gmss
{

	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using CryptoServicesRegistrar = CryptoServicesRegistrar;
	using Digest = org.bouncycastle.crypto.Digest;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using GMSSRandom = org.bouncycastle.pqc.crypto.gmss.util.GMSSRandom;
	using GMSSUtil = org.bouncycastle.pqc.crypto.gmss.util.GMSSUtil;
	using WinternitzOTSVerify = org.bouncycastle.pqc.crypto.gmss.util.WinternitzOTSVerify;
	using WinternitzOTSignature = org.bouncycastle.pqc.crypto.gmss.util.WinternitzOTSignature;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// This class implements the GMSS signature scheme.
	/// </summary>
	public class GMSSSigner : MessageSigner
	{

		/// <summary>
		/// Instance of GMSSParameterSpec
		/// </summary>
		//private GMSSParameterSpec gmssParameterSpec;

		/// <summary>
		/// Instance of GMSSUtilities
		/// </summary>
		private GMSSUtil gmssUtil = new GMSSUtil();


		/// <summary>
		/// The raw GMSS public key
		/// </summary>
		private byte[] pubKeyBytes;

		/// <summary>
		/// Hash function for the construction of the authentication trees
		/// </summary>
		private Digest messDigestTrees;

		/// <summary>
		/// The length of the hash function output
		/// </summary>
		private int mdLength;

		/// <summary>
		/// The number of tree layers
		/// </summary>
		private int numLayer;

		/// <summary>
		/// The hash function used by the OTS
		/// </summary>
		private Digest messDigestOTS;

		/// <summary>
		/// An instance of the Winternitz one-time signature
		/// </summary>
		private WinternitzOTSignature ots;

		/// <summary>
		/// Array of strings containing the name of the hash function used by the OTS
		/// and the corresponding provider name
		/// </summary>
		private GMSSDigestProvider digestProvider;

		/// <summary>
		/// The current main tree and subtree indices
		/// </summary>
		private int[] index;

		/// <summary>
		/// Array of the authentication paths for the current trees of all layers
		/// </summary>
		private byte[][][] currentAuthPaths;

		/// <summary>
		/// The one-time signature of the roots of the current subtrees
		/// </summary>
		private byte[][] subtreeRootSig;


		/// <summary>
		/// The GMSSParameterset
		/// </summary>
		private GMSSParameters gmssPS;

		/// <summary>
		/// The PRNG
		/// </summary>
		private GMSSRandom gmssRandom;

		internal GMSSKeyParameters key;

		// XXX needed? Source of randomness
		private SecureRandom random;


		/// <summary>
		/// The standard constructor tries to generate the MerkleTree Algorithm
		/// identifier with the corresponding OID.
		/// </summary>
		/// <param name="digest">     the digest to use </param>
		// TODO
		public GMSSSigner(GMSSDigestProvider digest)
		{
			digestProvider = digest;
			messDigestTrees = digest.get();
			messDigestOTS = messDigestTrees;
			mdLength = messDigestTrees.getDigestSize();
			gmssRandom = new GMSSRandom(messDigestTrees);
		}

		public virtual void init(bool forSigning, CipherParameters param)
		{

			if (forSigning)
			{
				if (param is ParametersWithRandom)
				{
					ParametersWithRandom rParam = (ParametersWithRandom)param;

					// XXX random needed?
					this.random = rParam.getRandom();
					this.key = (GMSSPrivateKeyParameters)rParam.getParameters();
					initSign();

				}
				else
				{

					this.random = CryptoServicesRegistrar.getSecureRandom();
					this.key = (GMSSPrivateKeyParameters)param;
					initSign();
				}
			}
			else
			{
				this.key = (GMSSPublicKeyParameters)param;
				initVerify();

			}

		}


		/// <summary>
		/// Initializes the signature algorithm for signing a message.
		/// </summary>
		private void initSign()
		{
			messDigestTrees.reset();
			// set private key and take from it ots key, auth, tree and key
			// counter, rootSign
			GMSSPrivateKeyParameters gmssPrivateKey = (GMSSPrivateKeyParameters)key;

			if (gmssPrivateKey.isUsed())
			{
				throw new IllegalStateException("Private key already used");
			}

			// check if last signature has been generated
			if (gmssPrivateKey.getIndex(0) >= gmssPrivateKey.getNumLeafs(0))
			{
				throw new IllegalStateException("No more signatures can be generated");
			}

			// get Parameterset
			this.gmssPS = gmssPrivateKey.getParameters();
			// get numLayer
			this.numLayer = gmssPS.getNumOfLayers();

			// get OTS Instance of lowest layer
			byte[] seed = gmssPrivateKey.getCurrentSeeds()[numLayer - 1];
			byte[] OTSSeed = new byte[mdLength];
			byte[] dummy = new byte[mdLength];
			JavaSystem.arraycopy(seed, 0, dummy, 0, mdLength);
			OTSSeed = gmssRandom.nextSeed(dummy); // secureRandom.nextBytes(currentSeeds[currentSeeds.length-1]);secureRandom.nextBytes(OTSseed);
			this.ots = new WinternitzOTSignature(OTSSeed, digestProvider.get(), gmssPS.getWinternitzParameter()[numLayer - 1]);

			byte[][][] helpCurrentAuthPaths = gmssPrivateKey.getCurrentAuthPaths();
			currentAuthPaths = new byte[numLayer][][];

			// copy the main tree authentication path
			for (int j = 0; j < numLayer; j++)
			{

				currentAuthPaths[j] = RectangularArrays.ReturnRectangularSbyteArray(helpCurrentAuthPaths[j].Length, mdLength);
				for (int i = 0; i < helpCurrentAuthPaths[j].Length; i++)
				{
					JavaSystem.arraycopy(helpCurrentAuthPaths[j][i], 0, currentAuthPaths[j][i], 0, mdLength);
				}
			}

			// copy index
			index = new int[numLayer];
			JavaSystem.arraycopy(gmssPrivateKey.getIndex(), 0, index, 0, numLayer);

			// copy subtreeRootSig
			byte[] helpSubtreeRootSig;
			subtreeRootSig = new byte[numLayer - 1][];
			for (int i = 0; i < numLayer - 1; i++)
			{
				helpSubtreeRootSig = gmssPrivateKey.getSubtreeRootSig(i);
				subtreeRootSig[i] = new byte[helpSubtreeRootSig.Length];
				JavaSystem.arraycopy(helpSubtreeRootSig, 0, subtreeRootSig[i], 0, helpSubtreeRootSig.Length);
			}

			gmssPrivateKey.markUsed();
		}

		/// <summary>
		/// Signs a message.
		/// </summary>
		/// <returns> the signature. </returns>
		public virtual byte[] generateSignature(byte[] message)
		{

			byte[] otsSig = new byte[mdLength];
			byte[] authPathBytes;
			byte[] indexBytes;

			otsSig = ots.getSignature(message);

			// get concatenated lowest layer tree authentication path
			authPathBytes = gmssUtil.concatenateArray(currentAuthPaths[numLayer - 1]);

			// put lowest layer index into a byte array
			indexBytes = gmssUtil.intToBytesLittleEndian(index[numLayer - 1]);

			// create first part of GMSS signature
			byte[] gmssSigFirstPart = new byte[indexBytes.Length + otsSig.Length + authPathBytes.Length];
			JavaSystem.arraycopy(indexBytes, 0, gmssSigFirstPart, 0, indexBytes.Length);
			JavaSystem.arraycopy(otsSig, 0, gmssSigFirstPart, indexBytes.Length, otsSig.Length);
			JavaSystem.arraycopy(authPathBytes, 0, gmssSigFirstPart, (indexBytes.Length + otsSig.Length), authPathBytes.Length);
			// --- end first part

			// --- next parts of the signature
			// create initial array with length 0 for iteration
			byte[] gmssSigNextPart = new byte[0];

			for (int i = numLayer - 1 - 1; i >= 0; i--)
			{

				// get concatenated next tree authentication path
				authPathBytes = gmssUtil.concatenateArray(currentAuthPaths[i]);

				// put next tree index into a byte array
				indexBytes = gmssUtil.intToBytesLittleEndian(index[i]);

				// create next part of GMSS signature

				// create help array and copy actual gmssSig into it
				byte[] helpGmssSig = new byte[gmssSigNextPart.Length];
				JavaSystem.arraycopy(gmssSigNextPart, 0, helpGmssSig, 0, gmssSigNextPart.Length);
				// adjust length of gmssSigNextPart for adding next part
				gmssSigNextPart = new byte[helpGmssSig.Length + indexBytes.Length + subtreeRootSig[i].Length + authPathBytes.Length];

				// copy old data (help array) and new data in gmssSigNextPart
				JavaSystem.arraycopy(helpGmssSig, 0, gmssSigNextPart, 0, helpGmssSig.Length);
				JavaSystem.arraycopy(indexBytes, 0, gmssSigNextPart, helpGmssSig.Length, indexBytes.Length);
				JavaSystem.arraycopy(subtreeRootSig[i], 0, gmssSigNextPart, (helpGmssSig.Length + indexBytes.Length), subtreeRootSig[i].Length);
				JavaSystem.arraycopy(authPathBytes, 0, gmssSigNextPart, (helpGmssSig.Length + indexBytes.Length + subtreeRootSig[i].Length), authPathBytes.Length);

			}
			// --- end next parts

			// concatenate the two parts of the GMSS signature
			byte[] gmssSig = new byte[gmssSigFirstPart.Length + gmssSigNextPart.Length];
			JavaSystem.arraycopy(gmssSigFirstPart, 0, gmssSig, 0, gmssSigFirstPart.Length);
			JavaSystem.arraycopy(gmssSigNextPart, 0, gmssSig, gmssSigFirstPart.Length, gmssSigNextPart.Length);

			// return the GMSS signature
			return gmssSig;
		}

		/// <summary>
		/// Initializes the signature algorithm for verifying a signature.
		/// </summary>
		private void initVerify()
		{
			messDigestTrees.reset();

			GMSSPublicKeyParameters gmssPublicKey = (GMSSPublicKeyParameters)key;
			pubKeyBytes = gmssPublicKey.getPublicKey();
			gmssPS = gmssPublicKey.getParameters();
			// get numLayer
			this.numLayer = gmssPS.getNumOfLayers();


		}

		/// <summary>
		/// This function verifies the signature of the message that has been
		/// updated, with the aid of the public key.
		/// </summary>
		/// <param name="message"> the message </param>
		/// <param name="signature"> the signature associated with the message </param>
		/// <returns> true if the signature has been verified, false otherwise. </returns>
		public virtual bool verifySignature(byte[] message, byte[] signature)
		{

			bool success = false;
			// int halfSigLength = signature.length >>> 1;
			messDigestOTS.reset();
			WinternitzOTSVerify otsVerify;
			int otsSigLength;

			byte[] help = message;

			byte[] otsSig;
			byte[] otsPublicKey;
			byte[][] authPath;
			byte[] dest;
			int nextEntry = 0;
			int index;
			// Verify signature

			// --- begin with message = 'message that was signed'
			// and then in each step message = subtree root
			for (int j = numLayer - 1; j >= 0; j--)
			{
				otsVerify = new WinternitzOTSVerify(digestProvider.get(), gmssPS.getWinternitzParameter()[j]);
				otsSigLength = otsVerify.getSignatureLength();

				message = help;
				// get the subtree index
				index = gmssUtil.bytesToIntLittleEndian(signature, nextEntry);

				// 4 is the number of bytes in integer
				nextEntry += 4;

				// get one-time signature
				otsSig = new byte[otsSigLength];
				JavaSystem.arraycopy(signature, nextEntry, otsSig, 0, otsSigLength);
				nextEntry += otsSigLength;

				// compute public OTS key from the one-time signature
				otsPublicKey = otsVerify.Verify(message, otsSig);

				// test if OTSsignature is correct
				if (otsPublicKey == null)
				{
					JavaSystem.err.println("OTS Public Key is null in GMSSSignature.verify");
					return false;
				}

				// get authentication path from the signature

				authPath = RectangularArrays.ReturnRectangularSbyteArray(gmssPS.getHeightOfTrees()[j], mdLength);
				for (int i = 0; i < authPath.Length; i++)
				{
					JavaSystem.arraycopy(signature, nextEntry, authPath[i], 0, mdLength);
					nextEntry = nextEntry + mdLength;
				}

				// compute the root of the subtree from the authentication path
				help = new byte[mdLength];

				help = otsPublicKey;

				int count = 1 << authPath.Length;
				count = count + index;

				for (int i = 0; i < authPath.Length; i++)
				{
					dest = new byte[mdLength << 1];

					if ((count % 2) == 0)
					{
						JavaSystem.arraycopy(help, 0, dest, 0, mdLength);
						JavaSystem.arraycopy(authPath[i], 0, dest, mdLength, mdLength);
						count = count / 2;
					}
					else
					{
						JavaSystem.arraycopy(authPath[i], 0, dest, 0, mdLength);
						JavaSystem.arraycopy(help, 0, dest, mdLength, help.Length);
						count = (count - 1) / 2;
					}
					messDigestTrees.update(dest, 0, dest.Length);
					help = new byte[messDigestTrees.getDigestSize()];
					messDigestTrees.doFinal(help, 0);
				}
			}

			// now help contains the root of the maintree

			// test if help is equal to the GMSS public key
			if (Arrays.areEqual(pubKeyBytes, help))
			{
				success = true;
			}

			return success;
		}


	}
}