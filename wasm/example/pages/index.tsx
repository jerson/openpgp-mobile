import type {NextPage} from 'next'
import {GenerateSample} from "./caller";

const Home: NextPage = () => {
    return (
        <div>
            <button onClick={GenerateSample}>Generate sample</button>
        </div>
    )
}

export default Home
