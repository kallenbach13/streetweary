import { useHistory, useParams } from 'react-router-dom' 

const CheckOutDone = () => {
  
    const history = useHistory()
    let { id } = useParams()

    const handleKeepShoppingClick = () => {
        history.push('/')
    }

    return (
        <div>
            <div>
                <p className="font-bold font-serif text-center text-xl my-8 text-gray-700 text-base">
                  Payment Succesful. Order Nr: {id}
                </p>
            </div>
            <div className="text-center">
              <button
                  className="m-4 py-2 px-4 cursor-pointer border border-transparent shadow-sm text-sm font-medium font-serif rounded-md text-white bg-pink-300 hover:bg-pink-400 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-pink-400"
                  onClick={handleKeepShoppingClick}>
                  Keep Shopping
              </button>  
            </div>
        </div>
      )
}
    
export default CheckOutDone