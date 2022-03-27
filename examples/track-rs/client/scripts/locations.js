const fs = require('fs');
function parsed_data() {
    let apiData = {location_data: []};

    let read = fs.readFileSync('2019_AUGUST.json');

    let data = JSON.parse(read);

    let count = 1;

    data.timelineObjects.forEach(function (obj) {
        if (Object.keys(obj) == 'placeVisit') {
            // let user = "User" + count;
            let lat = obj.placeVisit.location.latitudeE7 / 10000000
            let lng = obj.placeVisit.location.longitudeE7 / 10000000
            let startTime = Math.floor(new Date(obj.placeVisit.duration.startTimestamp).valueOf()/1000);
            let endTime = Math.floor(new Date(obj.placeVisit.duration.endTimestamp).valueOf()/1000);
            let randomBool = Math.random() > 0.1 ? false : true;


            apiData.location_data.push({"lat": lat, "lng": lng, "startTS": startTime, "endTS": endTime, "testResult": randomBool});


        }

    });

    fs.writeFileSync("data.json", JSON.stringify(apiData.location_data, null, 4));
    return apiData;
    }

parsed_data();


