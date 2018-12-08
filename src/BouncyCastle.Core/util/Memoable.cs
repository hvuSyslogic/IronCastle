using org.bouncycastle.Port;

namespace org.bouncycastle.util
{
	/// <summary>
	/// Interface for Memoable objects. Memoable objects allow the taking of a snapshot of their internal state
	/// via the copy() method and then reseting the object back to that state later using the reset() method.
	/// </summary>
	public interface Memoable
	{
		/// <summary>
		/// Produce a copy of this object with its configuration and in its current state.
		/// <para>
		/// The returned object may be used simply to store the state, or may be used as a similar object
		/// starting from the copied state.
		/// </para>
		/// </summary>
		Memoable copy();

		/// <summary>
		/// Restore a copied object state into this object.
		/// <para>
		/// Implementations of this method <em>should</em> try to avoid or minimise memory allocation to perform the reset.
		/// 
		/// </para>
		/// </summary>
		/// <param name="other"> an object originally <seealso cref="#copy() copied"/> from an object of the same type as this instance. </param>
		/// <exception cref="ClassCastException"> if the provided object is not of the correct type. </exception>
		/// <exception cref="MemoableResetException"> if the <b>other</b> parameter is in some other way invalid. </exception>
		void reset(Memoable other);
	}

}