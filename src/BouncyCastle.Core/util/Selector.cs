using BouncyCastle.Core.Port.java.lang;

namespace org.bouncycastle.util
{
	/// <summary>
	/// Interface a selector from a store should conform to.
	/// </summary>
	/// @param <T> the type stored in the store. </param>
	public interface Selector<T> : Cloneable
	{
		/// <summary>
		/// Match the passed in object, returning true if it would be selected by this selector, false otherwise.
		/// </summary>
		/// <param name="obj"> the object to be matched. </param>
		/// <returns> true if the object is a match for this selector, false otherwise. </returns>
		bool match(T obj);

		object clone();
	}

}