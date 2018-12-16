using System;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.pqc.crypto.gmss
{

	using Digest = org.bouncycastle.crypto.Digest;
	using GMSSRandom = org.bouncycastle.pqc.crypto.gmss.util.GMSSRandom;
	using WinternitzOTSignature = org.bouncycastle.pqc.crypto.gmss.util.WinternitzOTSignature;
	using Arrays = org.bouncycastle.util.Arrays;


	/// <summary>
	/// This class provides a specification for a GMSS private key.
	/// </summary>
	public class GMSSPrivateKeyParameters : GMSSKeyParameters
	{
		private int[] index;

		private byte[][] currentSeeds;
		private byte[][] nextNextSeeds;

		private byte[][][] currentAuthPaths;
		private byte[][][] nextAuthPaths;

		private Treehash[][] currentTreehash;
		private Treehash[][] nextTreehash;

		private Vector[] currentStack;
		private Vector[] nextStack;

		private Vector[][] currentRetain;
		private Vector[][] nextRetain;

		private byte[][][] keep;

		private GMSSLeaf[] nextNextLeaf;
		private GMSSLeaf[] upperLeaf;
		private GMSSLeaf[] upperTreehashLeaf;

		private int[] minTreehash;

		private GMSSParameters gmssPS;

		private byte[][] nextRoot;
		private GMSSRootCalc[] nextNextRoot;

		private byte[][] currentRootSig;
		private GMSSRootSig[] nextRootSig;

		private GMSSDigestProvider digestProvider;

		private bool used = false;

		/// <summary>
		/// An array of the heights of the authentication trees of each layer
		/// </summary>
		private int[] heightOfTrees;

		/// <summary>
		/// An array of the Winternitz parameter 'w' of each layer
		/// </summary>
		private int[] otsIndex;

		/// <summary>
		/// The parameter K needed for the authentication path computation
		/// </summary>
		private int[] K;

		/// <summary>
		/// the number of Layers
		/// </summary>
		private int numLayer;

		/// <summary>
		/// The hash function used to construct the authentication trees
		/// </summary>
		private Digest messDigestTrees;

		/// <summary>
		/// The message digest length
		/// </summary>
		private int mdLength;

		/// <summary>
		/// The PRNG used for private key generation
		/// </summary>
		private GMSSRandom gmssRandom;


		/// <summary>
		/// The number of leafs of one tree of each layer
		/// </summary>
		private int[] numLeafs;


		/// <summary>
		/// Generates a new GMSS private key
		/// </summary>
		/// <param name="currentSeed">      seed for the generation of private OTS keys for the
		///                         current subtrees </param>
		/// <param name="nextNextSeed">     seed for the generation of private OTS keys for the next
		///                         subtrees </param>
		/// <param name="currentAuthPath">  array of current authentication paths </param>
		/// <param name="nextAuthPath">     array of next authentication paths </param>
		/// <param name="currentTreehash">  array of current treehash instances </param>
		/// <param name="nextTreehash">     array of next treehash instances </param>
		/// <param name="currentStack">     array of current shared stacks </param>
		/// <param name="nextStack">        array of next shared stacks </param>
		/// <param name="currentRetain">    array of current retain stacks </param>
		/// <param name="nextRetain">       array of next retain stacks </param>
		/// <param name="nextRoot">         the roots of the next subtree </param>
		/// <param name="currentRootSig">   array of signatures of the roots of the current subtrees </param>
		/// <param name="gmssParameterset"> the GMSS Parameterset </param>
		/// <seealso cref= org.bouncycastle.pqc.crypto.gmss.GMSSKeyPairGenerator </seealso>

		public GMSSPrivateKeyParameters(byte[][] currentSeed, byte[][] nextNextSeed, byte[][][] currentAuthPath, byte[][][] nextAuthPath, Treehash[][] currentTreehash, Treehash[][] nextTreehash, Vector[] currentStack, Vector[] nextStack, Vector[][] currentRetain, Vector[][] nextRetain, byte[][] nextRoot, byte[][] currentRootSig, GMSSParameters gmssParameterset, GMSSDigestProvider digestProvider) : this(null, currentSeed, nextNextSeed, currentAuthPath, nextAuthPath, null, currentTreehash, nextTreehash, currentStack, nextStack, currentRetain, nextRetain, null, null, null, null, nextRoot, null, currentRootSig, null, gmssParameterset, digestProvider)
		{
		}

		/// <summary>
		/// /**
		/// </summary>
		/// <param name="index">             tree indices </param>
		/// <param name="keep">              keep array for the authPath algorithm </param>
		/// <param name="currentTreehash">   treehash for authPath algorithm of current tree </param>
		/// <param name="nextTreehash">      treehash for authPath algorithm of next tree (TREE+) </param>
		/// <param name="currentStack">      shared stack for authPath algorithm of current tree </param>
		/// <param name="nextStack">         shared stack for authPath algorithm of next tree (TREE+) </param>
		/// <param name="currentRetain">     retain stack for authPath algorithm of current tree </param>
		/// <param name="nextRetain">        retain stack for authPath algorithm of next tree (TREE+) </param>
		/// <param name="nextNextLeaf">      array of upcoming leafs of the tree after next (LEAF++) of
		///                          each layer </param>
		/// <param name="upperLeaf">         needed for precomputation of upper nodes </param>
		/// <param name="upperTreehashLeaf"> needed for precomputation of upper treehash nodes </param>
		/// <param name="minTreehash">       index of next treehash instance to receive an update </param>
		/// <param name="nextRoot">          the roots of the next trees (ROOT+) </param>
		/// <param name="nextNextRoot">      the roots of the tree after next (ROOT++) </param>
		/// <param name="currentRootSig">    array of signatures of the roots of the current subtrees
		///                          (SIG) </param>
		/// <param name="nextRootSig">       array of signatures of the roots of the next subtree
		///                          (SIG+) </param>
		/// <param name="gmssParameterset">  the GMSS Parameterset </param>
		public GMSSPrivateKeyParameters(int[] index, byte[][] currentSeeds, byte[][] nextNextSeeds, byte[][][] currentAuthPaths, byte[][][] nextAuthPaths, byte[][][] keep, Treehash[][] currentTreehash, Treehash[][] nextTreehash, Vector[] currentStack, Vector[] nextStack, Vector[][] currentRetain, Vector[][] nextRetain, GMSSLeaf[] nextNextLeaf, GMSSLeaf[] upperLeaf, GMSSLeaf[] upperTreehashLeaf, int[] minTreehash, byte[][] nextRoot, GMSSRootCalc[] nextNextRoot, byte[][] currentRootSig, GMSSRootSig[] nextRootSig, GMSSParameters gmssParameterset, GMSSDigestProvider digestProvider) : base(true, gmssParameterset)
		{


			// construct message digest

			this.messDigestTrees = digestProvider.get();
			this.mdLength = messDigestTrees.getDigestSize();


			// Parameter
			this.gmssPS = gmssParameterset;
			this.otsIndex = gmssParameterset.getWinternitzParameter();
			this.K = gmssParameterset.getK();
			this.heightOfTrees = gmssParameterset.getHeightOfTrees();
			// initialize numLayer
			this.numLayer = gmssPS.getNumOfLayers();

			// initialize index if null
			if (index == null)
			{
				this.index = new int[numLayer];
				for (int i = 0; i < numLayer; i++)
				{
					this.index[i] = 0;
				}
			}
			else
			{
				this.index = index;
			}

			this.currentSeeds = currentSeeds;
			this.nextNextSeeds = nextNextSeeds;

			this.currentAuthPaths = Arrays.clone(currentAuthPaths);
			this.nextAuthPaths = nextAuthPaths;

			// initialize keep if null
			if (keep == null)
			{
				this.keep = new byte[numLayer][][];
				for (int i = 0; i < numLayer; i++)
				{
					this.keep[i] = RectangularArrays.ReturnRectangularSbyteArray((int)Math.Floor((double) (heightOfTrees[i] / 2)), mdLength);
				}
			}
			else
			{
				this.keep = keep;
			}

			// initialize stack if null
			if (currentStack == null)
			{
				this.currentStack = new Vector[numLayer];
				for (int i = 0; i < numLayer; i++)
				{
					this.currentStack[i] = new Vector();
				}
			}
			else
			{
				this.currentStack = currentStack;
			}

			// initialize nextStack if null
			if (nextStack == null)
			{
				this.nextStack = new Vector[numLayer - 1];
				for (int i = 0; i < numLayer - 1; i++)
				{
					this.nextStack[i] = new Vector();
				}
			}
			else
			{
				this.nextStack = nextStack;
			}

			this.currentTreehash = currentTreehash;
			this.nextTreehash = nextTreehash;

			this.currentRetain = currentRetain;
			this.nextRetain = nextRetain;

			this.nextRoot = nextRoot;

			this.digestProvider = digestProvider;

			if (nextNextRoot == null)
			{
				this.nextNextRoot = new GMSSRootCalc[numLayer - 1];
				for (int i = 0; i < numLayer - 1; i++)
				{
					this.nextNextRoot[i] = new GMSSRootCalc(this.heightOfTrees[i + 1], this.K[i + 1], this.digestProvider);
				}
			}
			else
			{
				this.nextNextRoot = nextNextRoot;
			}
			this.currentRootSig = currentRootSig;

			// calculate numLeafs
			numLeafs = new int[numLayer];
			for (int i = 0; i < numLayer; i++)
			{
				numLeafs[i] = 1 << heightOfTrees[i];
			}
			// construct PRNG
			this.gmssRandom = new GMSSRandom(messDigestTrees);

			if (numLayer > 1)
			{
				// construct the nextNextLeaf (LEAFs++) array for upcoming leafs in
				// tree after next (TREE++)
				if (nextNextLeaf == null)
				{
					this.nextNextLeaf = new GMSSLeaf[numLayer - 2];
					for (int i = 0; i < numLayer - 2; i++)
					{
						this.nextNextLeaf[i] = new GMSSLeaf(digestProvider.get(), otsIndex[i + 1], numLeafs[i + 2], this.nextNextSeeds[i]);
					}
				}
				else
				{
					this.nextNextLeaf = nextNextLeaf;
				}
			}
			else
			{
				this.nextNextLeaf = new GMSSLeaf[0];
			}

			// construct the upperLeaf array for upcoming leafs in tree over the
			// actual
			if (upperLeaf == null)
			{
				this.upperLeaf = new GMSSLeaf[numLayer - 1];
				for (int i = 0; i < numLayer - 1; i++)
				{
					this.upperLeaf[i] = new GMSSLeaf(digestProvider.get(), otsIndex[i], numLeafs[i + 1], this.currentSeeds[i]);
				}
			}
			else
			{
				this.upperLeaf = upperLeaf;
			}

			// construct the leafs for upcoming leafs in treehashs in tree over the
			// actual
			if (upperTreehashLeaf == null)
			{
				this.upperTreehashLeaf = new GMSSLeaf[numLayer - 1];
				for (int i = 0; i < numLayer - 1; i++)
				{
					this.upperTreehashLeaf[i] = new GMSSLeaf(digestProvider.get(), otsIndex[i], numLeafs[i + 1]);
				}
			}
			else
			{
				this.upperTreehashLeaf = upperTreehashLeaf;
			}

			if (minTreehash == null)
			{
				this.minTreehash = new int[numLayer - 1];
				for (int i = 0; i < numLayer - 1; i++)
				{
					this.minTreehash[i] = -1;
				}
			}
			else
			{
				this.minTreehash = minTreehash;
			}

			// construct the nextRootSig (RootSig++)
			byte[] dummy = new byte[mdLength];
			byte[] OTSseed = new byte[mdLength];
			if (nextRootSig == null)
			{
				this.nextRootSig = new GMSSRootSig[numLayer - 1];
				for (int i = 0; i < numLayer - 1; i++)
				{
					JavaSystem.arraycopy(currentSeeds[i], 0, dummy, 0, mdLength);
					gmssRandom.nextSeed(dummy);
					OTSseed = gmssRandom.nextSeed(dummy);
					this.nextRootSig[i] = new GMSSRootSig(digestProvider.get(), otsIndex[i], heightOfTrees[i + 1]);
					this.nextRootSig[i].initSign(OTSseed, nextRoot[i]);
				}
			}
			else
			{
				this.nextRootSig = nextRootSig;
			}
		}

		// we assume this only gets called from nextKey so used is never copied.
		private GMSSPrivateKeyParameters(GMSSPrivateKeyParameters original) : base(true, original.getParameters())
		{

			this.index = Arrays.clone(original.index);
			this.currentSeeds = Arrays.clone(original.currentSeeds);
			this.nextNextSeeds = Arrays.clone(original.nextNextSeeds);
			this.currentAuthPaths = Arrays.clone(original.currentAuthPaths);
			this.nextAuthPaths = Arrays.clone(original.nextAuthPaths);
			this.currentTreehash = original.currentTreehash;
			this.nextTreehash = original.nextTreehash;
			this.currentStack = original.currentStack;
			this.nextStack = original.nextStack;
			this.currentRetain = original.currentRetain;
			this.nextRetain = original.nextRetain;
			this.keep = Arrays.clone(original.keep);
			this.nextNextLeaf = original.nextNextLeaf;
			this.upperLeaf = original.upperLeaf;
			this.upperTreehashLeaf = original.upperTreehashLeaf;
			this.minTreehash = original.minTreehash;
			this.gmssPS = original.gmssPS;
			this.nextRoot = Arrays.clone(original.nextRoot);
			this.nextNextRoot = original.nextNextRoot;
			this.currentRootSig = original.currentRootSig;
			this.nextRootSig = original.nextRootSig;
			this.digestProvider = original.digestProvider;
			this.heightOfTrees = original.heightOfTrees;
			this.otsIndex = original.otsIndex;
			this.K = original.K;
			this.numLayer = original.numLayer;
			this.messDigestTrees = original.messDigestTrees;
			this.mdLength = original.mdLength;
			this.gmssRandom = original.gmssRandom;
			this.numLeafs = original.numLeafs;
		}

		public virtual bool isUsed()
		{
			return this.used;
		}

		public virtual void markUsed()
		{
			this.used = true;
		}

		public virtual GMSSPrivateKeyParameters nextKey()
		{
			GMSSPrivateKeyParameters nKey = new GMSSPrivateKeyParameters(this);

			nKey.nextKey(gmssPS.getNumOfLayers() - 1);

			return nKey;
		}

		/// <summary>
		/// This method updates the GMSS private key for the next signature
		/// </summary>
		/// <param name="layer"> the layer where the next key is processed </param>
		private void nextKey(int layer)
		{
			// only for lowest layer ( other layers indices are raised in nextTree()
			// method )
			if (layer == numLayer - 1)
			{
				index[layer]++;
			} // else JavaSystem.@out.println(" --- nextKey on layer " + layer + "
			// index is now : " + index[layer]);

			// if tree of this layer is depleted
			if (index[layer] == numLeafs[layer])
			{
				if (numLayer != 1)
				{
					nextTree(layer);
					index[layer] = 0;
				}
			}
			else
			{
				updateKey(layer);
			}
		}

		/// <summary>
		/// Switch to next subtree if the current one is depleted
		/// </summary>
		/// <param name="layer"> the layer where the next tree is processed </param>
		private void nextTree(int layer)
		{
			// JavaSystem.@out.println("NextTree method called on layer " + layer);
			// dont create next tree for the top layer
			if (layer > 0)
			{
				// raise index for upper layer
				index[layer - 1]++;

				// test if it is already the last tree
				bool lastTree = true;
				int z = layer;
				do
				{
					z--;
					if (index[z] < numLeafs[z])
					{
						lastTree = false;
					}
				} while (lastTree && (z > 0));

				// only construct next subtree if last one is not already in use
				if (!lastTree)
				{
					gmssRandom.nextSeed(currentSeeds[layer]);

					// last step of distributed signature calculation
					nextRootSig[layer - 1].updateSign();

					// last step of distributed leaf calculation for nextNextLeaf
					if (layer > 1)
					{
						nextNextLeaf[layer - 1 - 1] = nextNextLeaf[layer - 1 - 1].nextLeaf();
					}

					// last step of distributed leaf calculation for upper leaf
					upperLeaf[layer - 1] = upperLeaf[layer - 1].nextLeaf();

					// last step of distributed leaf calculation for all treehashs

					if (minTreehash[layer - 1] >= 0)
					{
						upperTreehashLeaf[layer - 1] = upperTreehashLeaf[layer - 1].nextLeaf();
						byte[] leaf = this.upperTreehashLeaf[layer - 1].getLeaf();
						// if update is required use the precomputed leaf to update
						// treehash
						try
						{
							currentTreehash[layer - 1][minTreehash[layer - 1]].update(this.gmssRandom, leaf);
							// JavaSystem.@out.println("UUUpdated TH " +
							// minTreehash[layer - 1]);
							if (currentTreehash[layer - 1][minTreehash[layer - 1]].wasFinished())
							{
								// JavaSystem.@out.println("FFFinished TH " +
								// minTreehash[layer - 1]);
							}
						}
						catch (Exception e)
						{
							JavaSystem.@out.println(e);
						}
					}

					// last step of nextNextAuthRoot calculation
					this.updateNextNextAuthRoot(layer);

					// ******************************************************** /

					// NOW: advance to next tree on layer 'layer'

					// NextRootSig --> currentRootSigs
					this.currentRootSig[layer - 1] = nextRootSig[layer - 1].getSig();

					// -----------------------

					// nextTreehash --> currentTreehash
					// nextNextTreehash --> nextTreehash
					for (int i = 0; i < heightOfTrees[layer] - K[layer]; i++)
					{
						this.currentTreehash[layer][i] = this.nextTreehash[layer - 1][i];
						this.nextTreehash[layer - 1][i] = this.nextNextRoot[layer - 1].getTreehash()[i];
					}

					// NextAuthPath --> currentAuthPath
					// nextNextAuthPath --> nextAuthPath
					for (int i = 0; i < heightOfTrees[layer]; i++)
					{
						JavaSystem.arraycopy(nextAuthPaths[layer - 1][i], 0, currentAuthPaths[layer][i], 0, mdLength);
						JavaSystem.arraycopy(nextNextRoot[layer - 1].getAuthPath()[i], 0, nextAuthPaths[layer - 1][i], 0, mdLength);
					}

					// nextRetain --> currentRetain
					// nextNextRetain --> nextRetain
					for (int i = 0; i < K[layer] - 1; i++)
					{
						this.currentRetain[layer][i] = this.nextRetain[layer - 1][i];
						this.nextRetain[layer - 1][i] = this.nextNextRoot[layer - 1].getRetain()[i];
					}

					// nextStack --> currentStack
					this.currentStack[layer] = this.nextStack[layer - 1];
					// nextNextStack --> nextStack
					this.nextStack[layer - 1] = this.nextNextRoot[layer - 1].getStack();

					// nextNextRoot --> nextRoot
					this.nextRoot[layer - 1] = this.nextNextRoot[layer - 1].getRoot();
					// -----------------------

					// -----------------
					byte[] OTSseed = new byte[mdLength];
					byte[] dummy = new byte[mdLength];
					// gmssRandom.setSeed(currentSeeds[layer]);
					JavaSystem.arraycopy(currentSeeds[layer - 1], 0, dummy, 0, mdLength);
					OTSseed = gmssRandom.nextSeed(dummy); // only need OTSSeed
					OTSseed = gmssRandom.nextSeed(dummy);
					OTSseed = gmssRandom.nextSeed(dummy);
					// nextWinSig[layer-1]=new
					// GMSSWinSig(OTSseed,algNames,otsIndex[layer-1],heightOfTrees[layer],nextRoot[layer-1]);
					nextRootSig[layer - 1].initSign(OTSseed, nextRoot[layer - 1]);

					// nextKey for upper layer
					nextKey(layer - 1);
				}
			}
		}

		/// <summary>
		/// This method computes the authpath (AUTH) for the current tree,
		/// Additionally the root signature for the next tree (SIG+), the authpath
		/// (AUTH++) and root (ROOT++) for the tree after next in layer
		/// <code>layer</code>, and the LEAF++^1 for the next next tree in the
		/// layer above are updated This method is used by nextKey()
		/// </summary>
		/// <param name="layer"> </param>
		private void updateKey(int layer)
		{
			// ----------current tree processing of actual layer---------
			// compute upcoming authpath for current Tree (AUTH)
			computeAuthPaths(layer);

			// -----------distributed calculations part------------
			// not for highest tree layer
			if (layer > 0)
			{

				// compute (partial) next leaf on TREE++ (not on layer 1 and 0)
				if (layer > 1)
				{
					nextNextLeaf[layer - 1 - 1] = nextNextLeaf[layer - 1 - 1].nextLeaf();
				}

				// compute (partial) next leaf on tree above (not on layer 0)
				upperLeaf[layer - 1] = upperLeaf[layer - 1].nextLeaf();

				// compute (partial) next leaf for all treehashs on tree above (not
				// on layer 0)

				int t = (int)Math.Floor((double)(this.getNumLeafs(layer) * 2) / (double)(this.heightOfTrees[layer - 1] - this.K[layer - 1]));

				if (index[layer] % t == 1)
				{
					// JavaSystem.@out.println(" layer: " + layer + " index: " +
					// index[layer] + " t : " + t);

					// take precomputed node for treehash update
					// ------------------------------------------------
					if (index[layer] > 1 && minTreehash[layer - 1] >= 0)
					{
						byte[] leaf = this.upperTreehashLeaf[layer - 1].getLeaf();
						// if update is required use the precomputed leaf to update
						// treehash
						try
						{
							currentTreehash[layer - 1][minTreehash[layer - 1]].update(this.gmssRandom, leaf);
							// JavaSystem.@out.println("Updated TH " + minTreehash[layer
							// - 1]);
							if (currentTreehash[layer - 1][minTreehash[layer - 1]].wasFinished())
							{
								// JavaSystem.@out.println("Finished TH " +
								// minTreehash[layer - 1]);
							}
						}
						catch (Exception e)
						{
							JavaSystem.@out.println(e);
						}
						// ------------------------------------------------
					}

					// initialize next leaf precomputation
					// ------------------------------------------------

					// get lowest index of treehashs
					this.minTreehash[layer - 1] = getMinTreehashIndex(layer - 1);

					if (this.minTreehash[layer - 1] >= 0)
					{
						// initialize leaf
						byte[] seed = this.currentTreehash[layer - 1][this.minTreehash[layer - 1]].getSeedActive();
						this.upperTreehashLeaf[layer - 1] = new GMSSLeaf(this.digestProvider.get(), this.otsIndex[layer - 1], t, seed);
						this.upperTreehashLeaf[layer - 1] = this.upperTreehashLeaf[layer - 1].nextLeaf();
						// JavaSystem.@out.println("restarted treehashleaf (" + (layer -
						// 1) + "," + this.minTreehash[layer - 1] + ")");
					}
					// ------------------------------------------------

				}
				else
				{
					// update the upper leaf for the treehash one step
					if (this.minTreehash[layer - 1] >= 0)
					{
						this.upperTreehashLeaf[layer - 1] = this.upperTreehashLeaf[layer - 1].nextLeaf();
						// if (minTreehash[layer - 1] > 3)
						// JavaSystem.@out.print("#");
					}
				}

				// compute (partial) the signature of ROOT+ (RootSig+) (not on top
				// layer)
				nextRootSig[layer - 1].updateSign();

				// compute (partial) AUTHPATH++ & ROOT++ (not on top layer)
				if (index[layer] == 1)
				{
					// init root and authpath calculation for tree after next
					// (AUTH++, ROOT++)
					this.nextNextRoot[layer - 1].initialize(new Vector());
				}

				// update root and authpath calculation for tree after next (AUTH++,
				// ROOT++)
				this.updateNextNextAuthRoot(layer);
			}
			// ----------- end distributed calculations part-----------------
		}

		/// <summary>
		/// This method returns the index of the next Treehash instance that should
		/// receive an update
		/// </summary>
		/// <param name="layer"> the layer of the GMSS tree </param>
		/// <returns> index of the treehash instance that should get the update </returns>
		private int getMinTreehashIndex(int layer)
		{
			int minTreehash = -1;
			for (int h = 0; h < heightOfTrees[layer] - K[layer]; h++)
			{
				if (currentTreehash[layer][h].wasInitialized() && !currentTreehash[layer][h].wasFinished())
				{
					if (minTreehash == -1)
					{
						minTreehash = h;
					}
					else if (currentTreehash[layer][h].getLowestNodeHeight() < currentTreehash[layer][minTreehash].getLowestNodeHeight())
					{
						minTreehash = h;
					}
				}
			}
			return minTreehash;
		}

		/// <summary>
		/// Computes the upcoming currentAuthpath of layer <code>layer</code> using
		/// the revisited authentication path computation of Dahmen/Schneider 2008
		/// </summary>
		/// <param name="layer"> the actual layer </param>
		private void computeAuthPaths(int layer)
		{

			int Phi = index[layer];
			int H = heightOfTrees[layer];
			int K = this.K[layer];

			// update all nextSeeds for seed scheduling
			for (int i = 0; i < H - K; i++)
			{
				currentTreehash[layer][i].updateNextSeed(gmssRandom);
			}

			// STEP 1 of Algorithm
			int Tau = heightOfPhi(Phi);

			byte[] OTSseed = new byte[mdLength];
			OTSseed = gmssRandom.nextSeed(currentSeeds[layer]);

			// STEP 2 of Algorithm
			// if phi's parent on height tau + 1 if left node, store auth_tau
			// in keep_tau.
			// TODO check it, formerly was
			// int L = Phi / (int) Math.floor(Math.pow(2, Tau + 1));
			// L %= 2;
			int L = ((int)((uint)Phi >> (Tau + 1))) & 1;

			byte[] tempKeep = new byte[mdLength];
			// store the keep node not in keep[layer][tau/2] because it might be in
			// use
			// wait until the space is freed in step 4a
			if (Tau < H - 1 && L == 0)
			{
				JavaSystem.arraycopy(currentAuthPaths[layer][Tau], 0, tempKeep, 0, mdLength);
			}

			byte[] help = new byte[mdLength];
			// STEP 3 of Algorithm
			// if phi is left child, compute and store leaf for next currentAuthPath
			// path,
			// (obtained by veriying current signature)
			if (Tau == 0)
			{
				// LEAFCALC !!!
				if (layer == numLayer - 1)
				{ // lowest layer computes the
					// necessary leaf completely at this
					// time
					WinternitzOTSignature ots = new WinternitzOTSignature(OTSseed, digestProvider.get(), otsIndex[layer]);
					help = ots.getPublicKey();
				}
				else
				{ // other layers use the precomputed leafs in
					// nextNextLeaf
					byte[] dummy = new byte[mdLength];
					JavaSystem.arraycopy(currentSeeds[layer], 0, dummy, 0, mdLength);
					gmssRandom.nextSeed(dummy);
					help = upperLeaf[layer].getLeaf();
					this.upperLeaf[layer].initLeafCalc(dummy);

					// WinternitzOTSVerify otsver = new
					// WinternitzOTSVerify(algNames, otsIndex[layer]);
					// byte[] help2 = otsver.Verify(currentRoot[layer],
					// currentRootSig[layer]);
					// JavaSystem.@out.println(" --- " + layer + " " +
					// ByteUtils.toHexString(help) + " " +
					// ByteUtils.toHexString(help2));
				}
				JavaSystem.arraycopy(help, 0, currentAuthPaths[layer][0], 0, mdLength);
			}
			else
			{
				// STEP 4a of Algorithm
				// get new left currentAuthPath node on height tau
				byte[] toBeHashed = new byte[mdLength << 1];
				JavaSystem.arraycopy(currentAuthPaths[layer][Tau - 1], 0, toBeHashed, 0, mdLength);
				// free the shared keep[layer][tau/2]
				JavaSystem.arraycopy(keep[layer][(int)Math.Floor((Tau - 1) / 2f)], 0, toBeHashed, mdLength, mdLength);
				messDigestTrees.update(toBeHashed, 0, toBeHashed.Length);
				currentAuthPaths[layer][Tau] = new byte[messDigestTrees.getDigestSize()];
				messDigestTrees.doFinal(currentAuthPaths[layer][Tau], 0);

				// STEP 4b and 4c of Algorithm
				// copy right nodes to currentAuthPath on height 0..Tau-1
				for (int i = 0; i < Tau; i++)
				{

					// STEP 4b of Algorithm
					// 1st: copy from treehashs
					if (i < H - K)
					{
						if (currentTreehash[layer][i].wasFinished())
						{
							JavaSystem.arraycopy(currentTreehash[layer][i].getFirstNode(), 0, currentAuthPaths[layer][i], 0, mdLength);
							currentTreehash[layer][i].destroy();
						}
						else
						{
							JavaSystem.err.println("Treehash (" + layer + "," + i + ") not finished when needed in AuthPathComputation");
						}
					}

					// 2nd: copy precomputed values from Retain
					if (i < H - 1 && i >= H - K)
					{
						if (currentRetain[layer][i - (H - K)].size() > 0)
						{
							// pop element from retain
							JavaSystem.arraycopy((byte[])currentRetain[layer][i - (H - K)].lastElement(), 0, currentAuthPaths[layer][i], 0, mdLength);
							currentRetain[layer][i - (H - K)].removeElementAt(currentRetain[layer][i - (H - K)].size() - 1);
						}
					}

					// STEP 4c of Algorithm
					// initialize new stack at heights 0..Tau-1
					if (i < H - K)
					{
						// create stacks anew
						int startPoint = Phi + 3 * (1 << i);
						if (startPoint < numLeafs[layer])
						{
							// if (layer < 2) {
							// JavaSystem.@out.println("initialized TH " + i + " on layer
							// " + layer);
							// }
							currentTreehash[layer][i].initialize();
						}
					}
				}
			}

			// now keep space is free to use
			if (Tau < H - 1 && L == 0)
			{
				JavaSystem.arraycopy(tempKeep, 0, keep[layer][(int)Math.Floor(Tau / 2f)], 0, mdLength);
			}

			// only update empty stack at height h if all other stacks have
			// tailnodes with height >h
			// finds active stack with lowest node height, choses lower index in
			// case of tie

			// on the lowest layer leafs must be computed at once, no precomputation
			// is possible. So all treehash updates are done at once here
			if (layer == numLayer - 1)
			{
				for (int tmp = 1; tmp <= (H - K) / 2; tmp++)
				{
					// index of the treehash instance that receives the next update
					int minTreehash = getMinTreehashIndex(layer);

					// if active treehash is found update with a leaf
					if (minTreehash >= 0)
					{
						try
						{
							byte[] seed = new byte[mdLength];
							JavaSystem.arraycopy(this.currentTreehash[layer][minTreehash].getSeedActive(), 0, seed, 0, mdLength);
							byte[] seed2 = gmssRandom.nextSeed(seed);
							WinternitzOTSignature ots = new WinternitzOTSignature(seed2, this.digestProvider.get(), this.otsIndex[layer]);
							byte[] leaf = ots.getPublicKey();
							currentTreehash[layer][minTreehash].update(this.gmssRandom, leaf);
						}
						catch (Exception e)
						{
							JavaSystem.@out.println(e);
						}
					}
				}
			}
			else
			{ // on higher layers the updates are done later
				this.minTreehash[layer] = getMinTreehashIndex(layer);
			}
		}

		/// <summary>
		/// Returns the largest h such that 2^h | Phi
		/// </summary>
		/// <param name="Phi"> the leaf index </param>
		/// <returns> The largest <code>h</code> with <code>2^h | Phi</code> if
		///         <code>Phi!=0</code> else return <code>-1</code> </returns>
		private int heightOfPhi(int Phi)
		{
			if (Phi == 0)
			{
				return -1;
			}
			int Tau = 0;
			int modul = 1;
			while (Phi % modul == 0)
			{
				modul *= 2;
				Tau += 1;
			}
			return Tau - 1;
		}

		/// <summary>
		/// Updates the authentication path and root calculation for the tree after
		/// next (AUTH++, ROOT++) in layer <code>layer</code>
		/// </summary>
		/// <param name="layer"> </param>
		private void updateNextNextAuthRoot(int layer)
		{

			byte[] OTSseed = new byte[mdLength];
			OTSseed = gmssRandom.nextSeed(nextNextSeeds[layer - 1]);

			// get the necessary leaf
			if (layer == numLayer - 1)
			{ // lowest layer computes the necessary
				// leaf completely at this time
				WinternitzOTSignature ots = new WinternitzOTSignature(OTSseed, digestProvider.get(), otsIndex[layer]);
				this.nextNextRoot[layer - 1].update(nextNextSeeds[layer - 1], ots.getPublicKey());
			}
			else
			{ // other layers use the precomputed leafs in nextNextLeaf
				this.nextNextRoot[layer - 1].update(nextNextSeeds[layer - 1], nextNextLeaf[layer - 1].getLeaf());
				this.nextNextLeaf[layer - 1].initLeafCalc(nextNextSeeds[layer - 1]);
			}
		}

		public virtual int[] getIndex()
		{
			return index;
		}

		/// <returns> The current index of layer i </returns>
		public virtual int getIndex(int i)
		{
			return index[i];
		}

		public virtual byte[][] getCurrentSeeds()
		{
			return Arrays.clone(currentSeeds);
		}

		public virtual byte[][][] getCurrentAuthPaths()
		{
			return Arrays.clone(currentAuthPaths);
		}

		/// <returns> The one-time signature of the root of the current subtree </returns>
		public virtual byte[] getSubtreeRootSig(int i)
		{
			return currentRootSig[i];
		}


		public virtual GMSSDigestProvider getName()
		{
			return digestProvider;
		}

		/// <returns> The number of leafs of each tree of layer i </returns>
		public virtual int getNumLeafs(int i)
		{
			return numLeafs[i];
		}
	}

}