const fs = require('fs');
function parsed_data() {
    let apiData = {location_data: []};

    let read = fs.readFileSync('2019_AUGUST.json');

    let data = JSON.parse(read);

    let count = 1;

    data.timelineObjects.forEach(function (obj) {
        if (Object.keys(obj) == 'placeVisit') {
            let user = "User" + count;
            let lat = obj.placeVisit.location.latitudeE7 / 10000000
            let lng = obj.placeVisit.location.longitudeE7 / 10000000
            let startTime = Math.floor(new Date(obj.placeVisit.duration.startTimestamp).valueOf()/1000);
            let endTime = Math.floor(new Date(obj.placeVisit.duration.endTimestamp).valueOf()/1000);
            let randomBool = Math.random() > 0.1 ? false : true;

            let obj_data = {"lat": lat, "lng": lng, "startTS": startTime, "endTS": endTime, "testResult": randomBool}

            // apiData.location_data.push({"lat": lat, "lng": lng, "startTS": startTime, "endTS": endTime, "testResult": randomBool});
            apiData.location_data.push(obj_data);
            // apiData.users.push({"userId": user});
            count++;

        }

    });

    fs.writeFileSync("data.json", JSON.stringify(apiData, null, 4));
    return apiData;
    }

parsed_data();

function loop_data() {
    let read = fs.readFileSync('data.json');

    let gps_location = JSON.parse(read);
    let data_array = gps_location.location_data;
    let chunklength = Math.max(data_array.length/2, 1);
    let chunks = [];
    for (let i = 0; i < 2; i++) {
        if(chunklength*(i+1)<=data_array.length) {
            chunks.push(data_array.slice(chunkLength * i, chunkLength * (i + 1)));
        }

    }
    //loop
    // data_array.map((item) => console.log('location:', item.data))

}

loop_data()